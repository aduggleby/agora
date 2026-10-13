using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Web;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Web.Pages;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// The emailed confirmation link is a page with a confirm button: opening it (as mail scanners and link previews
/// do) consumes nothing, only the antiforgery-protected POST from that page does. Runs the real Razor pages with
/// antiforgery and cookie authentication enabled against AuthService.
/// </summary>
public sealed class AuthConfirmationPageTests
{
    private const string Email = "newuser@example.com";

    [Fact]
    public async Task Confirm_email_link_is_consumed_by_the_post_not_the_get()
    {
        await using var host = await Host.StartAsync();
        var link = await host.RegisterAndGetLinkAsync();
        var token = HttpUtility.ParseQueryString(link.Query)["token"]!;

        // Opening the link twice (scanner, preview, the user) leaves the token intact.
        for (var i = 0; i < 2; i++)
        {
            var get = await host.GetAsync(link.PathAndQuery);
            Assert.Equal(HttpStatusCode.OK, get.Status);
            Assert.Equal("no-referrer", get.Headers["Referrer-Policy"]);
            Assert.Contains("Confirm email", get.Body);
            Assert.Contains(token, get.Body);
            Assert.Contains("action=\"/auth/confirm-email\"", get.Body);
            Assert.NotNull(Host.AntiforgeryField(get.Body));
            Assert.False(await host.IsConfirmedAsync());
        }

        var page = await host.GetAsync(link.PathAndQuery);
        var post = await host.PostAsync("/auth/confirm-email", new() { ["email"] = Email, ["token"] = token }, Host.AntiforgeryField(page.Body));
        Assert.Equal(HttpStatusCode.Redirect, post.Status);
        Assert.Equal("/login?msg=Email%20confirmed.%20You%20can%20now%20sign%20in", post.Headers["Location"]);
        Assert.True(await host.IsConfirmedAsync());

        // Second use of the same link fails without side effects.
        var replay = await host.PostAsync("/auth/confirm-email", new() { ["email"] = Email, ["token"] = token }, Host.AntiforgeryField(page.Body));
        Assert.Equal(HttpStatusCode.Redirect, replay.Status);
        Assert.StartsWith("/login?msg=", replay.Headers["Location"], StringComparison.Ordinal);
        Assert.NotEqual(post.Headers["Location"], replay.Headers["Location"]);
    }

    [Fact]
    public async Task Posts_without_a_valid_antiforgery_token_are_refused_and_consume_nothing()
    {
        await using var host = await Host.StartAsync();
        var link = await host.RegisterAndGetLinkAsync();
        var token = HttpUtility.ParseQueryString(link.Query)["token"]!;
        await host.GetAsync(link.PathAndQuery); // establishes the antiforgery cookie

        var missing = await host.PostAsync("/auth/confirm-email", new() { ["email"] = Email, ["token"] = token }, antiforgeryField: null);
        Assert.Equal(HttpStatusCode.BadRequest, missing.Status);

        var invalid = await host.PostAsync("/auth/confirm-email", new() { ["email"] = Email, ["token"] = token }, antiforgeryField: "not-a-real-antiforgery-token");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.Status);

        Assert.False(await host.IsConfirmedAsync());
    }

    [Fact]
    public async Task Failed_confirmation_while_signed_in_keeps_the_session()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync();
        Assert.Equal("authenticated", (await host.GetAsync("/test/whoami")).Body);

        var page = await host.GetAsync("/auth/confirm-password-change?email=someone%40example.com&token=stale");
        var post = await host.PostAsync("/auth/confirm-password-change", new() { ["email"] = "someone@example.com", ["token"] = "stale" }, Host.AntiforgeryField(page.Body));

        Assert.Equal(HttpStatusCode.Redirect, post.Status);
        Assert.StartsWith("/login?msg=", post.Headers["Location"], StringComparison.Ordinal);
        Assert.Equal("authenticated", (await host.GetAsync("/test/whoami")).Body);
    }

    [Fact]
    public async Task Reset_password_form_posts_to_a_query_free_action_with_the_antiforgery_field()
    {
        await using var host = await Host.StartAsync();

        var get = await host.GetAsync("/reset-password?email=a%40b.c&token=reset-token-1");

        Assert.Equal(HttpStatusCode.OK, get.Status);
        Assert.Equal("no-referrer", get.Headers["Referrer-Policy"]);
        Assert.Contains("action=\"/reset-password\"", get.Body);
        Assert.Contains("name=\"token\" value=\"reset-token-1\"", get.Body);
        Assert.NotNull(Host.AntiforgeryField(get.Body));
    }

    [Fact]
    public async Task Links_without_a_token_render_the_invalid_state_and_post_nothing()
    {
        await using var host = await Host.StartAsync();

        foreach (var route in new[] { "/auth/confirm-email", "/auth/confirm-email-change", "/auth/confirm-password-change" })
        {
            var get = await host.GetAsync(route + "?email=someone%40example.com");
            Assert.Equal(HttpStatusCode.OK, get.Status);
            Assert.Contains("This confirmation link is invalid", get.Body);

            var page = await host.GetAsync(route + "?email=someone%40example.com&token=x");
            var post = await host.PostAsync(route, new() { ["email"] = "someone@example.com" }, Host.AntiforgeryField(page.Body));
            Assert.Equal(HttpStatusCode.Redirect, post.Status);
            Assert.Equal("/login?msg=Confirmation%20link%20is%20invalid", post.Headers["Location"]);
        }
    }

    private sealed record Reply(HttpStatusCode Status, string Body, Dictionary<string, string> Headers);

    /// <summary>Test host with a cookie jar, so antiforgery and authentication cookies round-trip like in a browser.</summary>
    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly RecordingEmailSender _sender;
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        private Host(WebApplication app, SqliteConnection connection, RecordingEmailSender sender)
        {
            _app = app;
            _connection = connection;
            _sender = sender;
        }

        public static async Task<Host> StartAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var sender = new RecordingEmailSender();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddSingleton<IEmailSender>(sender);
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
            builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapRazorPages();
            app.MapGet("/test/signin", async (HttpContext ctx) =>
            {
                var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()), new Claim(ClaimTypes.Name, "signed@example.com")], CookieAuthenticationDefaults.AuthenticationScheme);
                await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
                return Results.Ok();
            });
            app.MapGet("/test/whoami", (HttpContext ctx) => Results.Text(ctx.User.Identity?.IsAuthenticated == true ? "authenticated" : "anonymous"));
            await app.StartAsync();

            using (var scope = app.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Database.EnsureCreatedAsync();
            }

            return new Host(app, connection, sender);
        }

        public async Task<Uri> RegisterAndGetLinkAsync()
        {
            using var scope = _app.Services.CreateScope();
            var auth = scope.ServiceProvider.GetRequiredService<AuthService>();
            var registered = await auth.RegisterAsync(Email, "a-strong-password", "https://files.example.com/auth/confirm-email", CancellationToken.None);
            Assert.True(registered.Success, registered.Error);
            var link = new Uri(Assert.Single(_sender.Messages).ActionUrl);
            Assert.Equal(Email, HttpUtility.ParseQueryString(link.Query)["email"]);
            return link;
        }

        public async Task<bool> IsConfirmedAsync()
        {
            using var scope = _app.Services.CreateScope();
            var user = await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Users.AsNoTracking().SingleAsync(x => x.Email == Email);
            return user.EmailConfirmed && user.EmailConfirmationTokenHash is null;
        }

        public Task SignInAsync() => GetAsync("/test/signin");

        public static string? AntiforgeryField(string html) =>
            Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"") is { Success: true } m ? m.Groups[1].Value : null;

        public Task<Reply> GetAsync(string pathAndQuery) => SendAsync(HttpMethods.Get, pathAndQuery, null);

        public Task<Reply> PostAsync(string path, Dictionary<string, string> fields, string? antiforgeryField)
        {
            if (antiforgeryField is not null)
            {
                fields["__RequestVerificationToken"] = antiforgeryField;
            }

            var body = string.Join("&", fields.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
            return SendAsync(HttpMethods.Post, path, body);
        }

        private async Task<Reply> SendAsync(string method, string pathAndQuery, string? formBody)
        {
            var uri = new Uri("http://localhost" + pathAndQuery);
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = method;
                ctx.Request.Path = uri.AbsolutePath;
                ctx.Request.QueryString = new QueryString(uri.Query);
                if (_cookies.Count > 0)
                {
                    ctx.Request.Headers.Cookie = string.Join("; ", _cookies.Select(kv => $"{kv.Key}={kv.Value}"));
                }

                if (formBody is not null)
                {
                    var bytes = System.Text.Encoding.UTF8.GetBytes(formBody);
                    ctx.Request.ContentType = "application/x-www-form-urlencoded";
                    ctx.Request.ContentLength = bytes.Length;
                    ctx.Request.Body = new MemoryStream(bytes);
                }
            });

            foreach (var setCookie in context.Response.Headers.SetCookie)
            {
                var parts = (setCookie ?? string.Empty).Split(';');
                var pair = parts[0].Split('=', 2);
                if (pair.Length != 2)
                {
                    continue;
                }

                var expired = parts.Any(p => p.Trim().StartsWith("expires=", StringComparison.OrdinalIgnoreCase) &&
                                             DateTimeOffset.TryParse(p.Trim()[8..], out var when) && when < DateTimeOffset.UtcNow);
                if (expired || pair[1].Length == 0)
                {
                    _cookies.Remove(pair[0]);
                }
                else
                {
                    _cookies[pair[0]] = pair[1];
                }
            }

            var body = await new StreamReader(context.Response.Body).ReadToEndAsync();
            var headers = context.Response.Headers.ToDictionary(h => h.Key, h => h.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            return new Reply((HttpStatusCode)context.Response.StatusCode, body, headers);
        }

        public async ValueTask DisposeAsync()
        {
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<AuthEmailMessage> Messages { get; } = [];
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
        {
            Messages.Add(message);
            return Task.CompletedTask;
        }
    }
}
