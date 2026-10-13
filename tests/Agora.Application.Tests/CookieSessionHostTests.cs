using System.Net;
using System.Security.Claims;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Web.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// Runs the real cookie scheme with <see cref="CookieSessions.ValidatePrincipalAsync"/> and
/// <see cref="CookieSessions.TryReissueAsync"/> (the Settings page's re-mint path) over a TestServer, with a
/// controllable clock so the revalidation interval can elapse without sleeping.
/// </summary>
public sealed class CookieSessionHostTests
{
    private const string Email = "user@example.com";
    private const string AuthCookie = ".AspNetCore.Cookies";

    [Fact]
    public async Task Password_reset_ends_other_sessions_once_the_interval_elapses()
    {
        await using var host = await TestHost.StartAsync(intervalMinutes: 5);
        var sessionA = host.NewSession();
        var sessionB = host.NewSession();
        await sessionA.LoginAsync();
        await sessionB.LoginAsync();
        Assert.Equal(HttpStatusCode.OK, (await sessionB.GetAsync("/me")).StatusCode);

        var stampBefore = await host.StampAsync();
        await host.ResetPasswordAsync();
        var stampAfter = await host.StampAsync();
        Assert.False(string.IsNullOrEmpty(stampAfter));
        Assert.NotEqual(stampBefore, stampAfter);

        host.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(HttpStatusCode.OK, (await sessionB.GetAsync("/me")).StatusCode);

        host.Clock.Advance(TimeSpan.FromMinutes(4));
        var rejected = await sessionB.GetAsync("/me");
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
        Assert.False(sessionB.HasCookie(AuthCookie));
        Assert.Equal(HttpStatusCode.Unauthorized, (await sessionA.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task Reissue_is_refused_for_a_cookie_whose_stamp_is_stale()
    {
        await using var host = await TestHost.StartAsync(intervalMinutes: 5);
        var session = host.NewSession();
        await session.LoginAsync();

        var stampBefore = await host.StampAsync();
        await host.PromoteAsync();
        Assert.NotEqual(stampBefore, await host.StampAsync());

        // Not yet due: the stale cookie is still accepted for plain requests.
        Assert.Equal(HttpStatusCode.OK, (await session.GetAsync("/me")).StatusCode);

        var reissue = await session.PostAsync("/reissue");
        Assert.Equal(HttpStatusCode.Unauthorized, reissue.StatusCode);
        Assert.DoesNotContain(IssuedCookies(reissue), value => !string.IsNullOrEmpty(value));
        Assert.False(session.HasCookie(AuthCookie));
        Assert.Equal(HttpStatusCode.Unauthorized, (await session.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task Reissue_with_live_stamp_signs_in_from_the_database_record()
    {
        await using var host = await TestHost.StartAsync(intervalMinutes: 5);
        var session = host.NewSession();
        await session.LoginAsync();
        await host.RenameAsync("Renamed");

        var reissue = await session.PostAsync("/reissue");
        Assert.Equal(HttpStatusCode.OK, reissue.StatusCode);
        Assert.Contains(IssuedCookies(reissue), value => !string.IsNullOrEmpty(value));

        var me = await session.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal("Renamed", me.Headers.GetValues("X-Name").Single());
    }

    [Fact]
    public async Task Due_revalidation_refreshes_claims_and_renews_the_cookie()
    {
        await using var host = await TestHost.StartAsync(intervalMinutes: 5);
        var session = host.NewSession();
        await session.LoginAsync();
        await host.RenameAsync("Renamed");

        var early = await session.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, early.StatusCode);
        Assert.Equal("user", early.Headers.GetValues("X-Name").Single());
        Assert.Empty(IssuedCookies(early));

        host.Clock.Advance(TimeSpan.FromMinutes(5));
        var refreshed = await session.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Equal("Renamed", refreshed.Headers.GetValues("X-Name").Single());
        Assert.Contains(IssuedCookies(refreshed), value => !string.IsNullOrEmpty(value));

        var again = await session.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Empty(IssuedCookies(again));
    }

    private static IReadOnlyList<string> IssuedCookies(HttpResponseMessage response)
    {
        return response.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.Where(v => v.StartsWith(AuthCookie + "=", StringComparison.Ordinal))
                .Select(v => v[(AuthCookie.Length + 1)..].Split(';')[0])
                .ToList()
            : [];
    }

    private sealed class TestClock(DateTime startUtc) : TimeProvider
    {
        private DateTimeOffset _now = new(startUtc);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class TestHost : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        public TestClock Clock { get; }

        private TestHost(WebApplication app, SqliteConnection connection, TestClock clock)
        {
            _app = app;
            _connection = connection;
            Clock = clock;
        }

        public static async Task<TestHost> StartAsync(int intervalMinutes)
        {
            var clock = new TestClock(new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc));
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<AgoraDbContext>(options => options.UseSqlite(connection));
            builder.Services.AddScoped(sp => new AuthService(sp.GetRequiredService<AgoraDbContext>(), new NoopEmailSender()));
            builder.Services.Configure<AgoraOptions>(options => options.Auth.SessionRevalidationMinutes = intervalMinutes);
            builder.Services.AddSingleton<TimeProvider>(clock);
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.TimeProvider = clock;
                    options.SlidingExpiration = true;
                    options.Events.OnValidatePrincipal = CookieSessions.ValidatePrincipalAsync;
                });

            var app = builder.Build();
            app.UseAuthentication();
            app.MapPost("/login", async (HttpContext context, AgoraDbContext db, CancellationToken ct) =>
            {
                var user = await db.Users.SingleAsync(x => x.Email == Email, ct);
                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(user, clock.GetUtcNow().UtcDateTime));
                return Results.Ok();
            });
            app.MapGet("/me", (HttpContext context) =>
            {
                if (context.User.Identity?.IsAuthenticated != true)
                {
                    return Results.Unauthorized();
                }

                context.Response.Headers["X-Name"] = context.User.FindFirstValue(ClaimTypes.Name);
                return Results.Ok();
            });
            app.MapPost("/reissue", async (HttpContext context, AgoraDbContext db, CancellationToken ct) =>
                await CookieSessions.TryReissueAsync(context, db, ct) ? Results.Ok() : Results.Unauthorized());
            await app.StartAsync();

            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(new UserAccount
                {
                    Id = Guid.NewGuid(),
                    Email = Email,
                    DisplayName = "user",
                    EmailConfirmed = true,
                    PasswordHash = PasswordHasher.Hash("CorrectHorseBatteryStaple!"),
                    SecurityStamp = SecurityStamps.New(),
                    Role = "user",
                    IsEnabled = true,
                    UploadToken = "seeduser",
                    CreatedAtUtc = clock.GetUtcNow().UtcDateTime
                });
                await db.SaveChangesAsync();
            }

            return new TestHost(app, connection, clock);
        }

        public Session NewSession() => new(_app.GetTestClient());

        public async Task<string> StampAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            return (await db.Users.AsNoTracking().SingleAsync(x => x.Email == Email)).SecurityStamp;
        }

        public async Task ResetPasswordAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var user = await db.Users.SingleAsync(x => x.Email == Email);
            user.PasswordResetTokenHash = TokenCodec.HashToken("reset-token");
            user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
            await db.SaveChangesAsync();

            var result = await scope.ServiceProvider.GetRequiredService<AuthService>()
                .ResetPasswordAsync(Email, "reset-token", "AnotherPassword123!", CancellationToken.None);
            Assert.True(result.Success, result.Error);
        }

        public async Task PromoteAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var user = await db.Users.AsNoTracking().SingleAsync(x => x.Email == Email);
            Assert.True(await scope.ServiceProvider.GetRequiredService<AuthService>().UpdateRoleAsync(user.Id, "admin", CancellationToken.None));
        }

        public async Task RenameAsync(string displayName)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var user = await db.Users.SingleAsync(x => x.Email == Email);
            user.DisplayName = displayName;
            await db.SaveChangesAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    /// <summary>A browser-like cookie jar over the TestServer client: sends stored cookies, applies Set-Cookie.</summary>
    private sealed class Session(HttpClient client)
    {
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        public bool HasCookie(string name) => _cookies.ContainsKey(name);

        public Task LoginAsync() => PostAsync("/login");

        public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(HttpMethod.Get, path);

        public Task<HttpResponseMessage> PostAsync(string path) => SendAsync(HttpMethod.Post, path);

        private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path)
        {
            using var request = new HttpRequestMessage(method, path);
            if (_cookies.Count > 0)
            {
                request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(x => $"{x.Key}={x.Value}")));
            }

            var response = await client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    var pair = setCookie.Split(';')[0];
                    var separator = pair.IndexOf('=', StringComparison.Ordinal);
                    var name = pair[..separator];
                    var value = pair[(separator + 1)..];
                    if (string.IsNullOrEmpty(value))
                    {
                        _cookies.Remove(name);
                    }
                    else
                    {
                        _cookies[name] = value;
                    }
                }
            }

            return response;
        }
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
