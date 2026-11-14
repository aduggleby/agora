using System.Net;
using System.Text.RegularExpressions;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Web.Auth;
using Agora.Web.Pages.Account;
using Agora.Web.Services;
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

/// <summary>Runs the real Settings page (agent tokens, access levels, agent upload switch) with antiforgery and cookie authentication.</summary>
public sealed class SettingsAgentPageTests
{
    [Fact]
    public async Task Create_token_renders_the_plaintext_once_and_stores_a_row_with_the_level()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        await host.SignInAsync(user);

        var page = await host.GetAsync("/account/settings");
        Assert.Equal(HttpStatusCode.OK, page.Status);
        Assert.DoesNotContain("data-agent-token-panel", page.Body);
        Assert.Matches("name=\"accessLevel\" value=\"own\" checked", page.Body);

        var created = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "  Report bot  ", ["accessLevel"] = "all" }, Host.Antiforgery(page.Body));
        Assert.Equal(HttpStatusCode.OK, created.Status);
        Assert.Contains("no-store", created.Headers["Cache-Control"]);
        Assert.False(created.Headers.ContainsKey("Location"));
        var token = Regex.Match(created.Body, "value=\"(agora_pat_[^\"]+)\"").Groups[1].Value;
        Assert.StartsWith(ApiTokens.TokenPrefix, token, StringComparison.Ordinal);
        Assert.Contains("shown only once", created.Body);
        Assert.Contains("data-copy-agent-token", created.Body);

        var row = await host.SingleTokenAsync();
        Assert.Equal(ApiTokens.AgentClientId, row.ClientId);
        Assert.Equal("all", row.AccessLevel);
        Assert.Equal("Report bot", row.DeviceName);
        Assert.Equal(user.Id, row.UserId);
        Assert.Contains("Agent token", created.Body);

        // A reload never shows the plaintext again.
        var reload = await host.GetAsync("/account/settings");
        Assert.DoesNotContain(token, reload.Body);
        Assert.DoesNotContain("data-agent-token-panel", reload.Body);
        Assert.Contains("Report bot", reload.Body);
    }

    [Fact]
    public async Task Create_token_defaults_to_own_and_rejects_an_empty_name()
    {
        await using var host = await Host.StartAsync();
        await host.SignInAsync(await host.SeedUserAsync("a@example.com"));
        var page = await host.GetAsync("/account/settings");

        var empty = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "   ", ["accessLevel"] = "own" }, Host.Antiforgery(page.Body));
        Assert.Equal(HttpStatusCode.Redirect, empty.Status);
        Assert.Equal(0, await host.TokenCountAsync());

        var bogus = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "Bot", ["accessLevel"] = "admin" }, Host.Antiforgery(page.Body));
        Assert.Equal(HttpStatusCode.OK, bogus.Status);
        Assert.Equal("own", (await host.SingleTokenAsync()).AccessLevel);
    }

    [Fact]
    public async Task Create_token_with_a_stale_session_stamp_creates_nothing()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        await host.SignInAsync(user);
        var page = await host.GetAsync("/account/settings");
        await host.RotateStampAsync(user.Id);

        var post = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "Bot", ["accessLevel"] = "own" }, Host.Antiforgery(page.Body));

        Assert.Equal(HttpStatusCode.Redirect, post.Status);
        Assert.DoesNotContain("agora_pat_", post.Body);
        Assert.Equal(0, await host.TokenCountAsync());
    }

    [Fact]
    public async Task Rows_show_their_kind_and_only_agent_rows_get_an_access_select()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        await host.AddTokenAsync(user.Id, ApiTokens.CaptureClientId, "My Mac", null);
        await host.AddTokenAsync(user.Id, "mcp:abc", "Claude Code", "own");
        await host.AddTokenAsync(user.Id, ApiTokens.AgentClientId, "Report bot", "all");
        await host.SignInAsync(user);

        var body = (await host.GetAsync("/account/settings")).Body;

        Assert.Contains(">Capture app<", body);
        Assert.Contains(">Agent sign-in<", body);
        Assert.Contains(">Agent token<", body);
        Assert.Equal(2, Regex.Matches(body, "data-app-access-form").Count);
        Assert.Equal(3, Regex.Matches(body, "data-revoke-app-form").Count);
        Assert.Contains("Only shares it creates", body);
        Assert.Contains("All my shares", body);
    }

    [Fact]
    public async Task Set_access_changes_the_level_for_own_agent_rows_only()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        var other = await host.SeedUserAsync("b@example.com");
        var agent = await host.AddTokenAsync(user.Id, ApiTokens.AgentClientId, "Bot", "own");
        var capture = await host.AddTokenAsync(user.Id, ApiTokens.CaptureClientId, "Mac", null);
        var foreign = await host.AddTokenAsync(other.Id, ApiTokens.AgentClientId, "Theirs", "own");
        await host.SignInAsync(user);
        var page = await host.GetAsync("/account/settings");
        var af = Host.Antiforgery(page.Body);

        var ok = await host.PostAsync("/account/settings?handler=SetAppAccess", new() { ["tokenId"] = agent.ToString(), ["accessLevel"] = "all" }, af);
        Assert.Equal(HttpStatusCode.Redirect, ok.Status);
        Assert.Equal("all", await host.LevelAsync(agent));

        await host.PostAsync("/account/settings?handler=SetAppAccess", new() { ["tokenId"] = capture.ToString(), ["accessLevel"] = "all" }, af);
        Assert.Null(await host.LevelAsync(capture));

        await host.PostAsync("/account/settings?handler=SetAppAccess", new() { ["tokenId"] = foreign.ToString(), ["accessLevel"] = "all" }, af);
        Assert.Equal("own", await host.LevelAsync(foreign));

        await host.PostAsync("/account/settings?handler=SetAppAccess", new() { ["tokenId"] = agent.ToString(), ["accessLevel"] = "root" }, af);
        Assert.Equal("all", await host.LevelAsync(agent));
    }

    [Fact]
    public async Task Revoke_disconnects_an_agent_and_cannot_touch_another_users_token()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        var other = await host.SeedUserAsync("b@example.com");
        var agent = await host.AddTokenAsync(user.Id, ApiTokens.AgentClientId, "Bot", "own");
        var foreign = await host.AddTokenAsync(other.Id, ApiTokens.AgentClientId, "Theirs", "own");
        await host.SignInAsync(user);
        var af = Host.Antiforgery((await host.GetAsync("/account/settings")).Body);

        await host.PostAsync("/account/settings?handler=RevokeApp", new() { ["tokenId"] = foreign.ToString() }, af);
        Assert.False(await host.IsRevokedAsync(foreign));

        await host.PostAsync("/account/settings?handler=RevokeApp", new() { ["tokenId"] = agent.ToString() }, af);
        Assert.True(await host.IsRevokedAsync(agent));
        Assert.Equal(0, Regex.Matches((await host.GetAsync("/account/settings")).Body, $"data-connected-app=\"{agent}\"").Count);
    }

    [Fact]
    public async Task Agent_uploads_switch_is_off_by_default_and_toggles_with_the_instructions_url()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        await host.SignInAsync(user);

        var off = await host.GetAsync("/account/settings");
        Assert.Contains("Let AI agents send files to my upload link", off.Body);
        Assert.DoesNotMatch("name=\"allowAgentUploads\"[^>]*checked", off.Body);
        Assert.DoesNotContain("llms.txt", off.Body);

        var af = Host.Antiforgery(off.Body);
        await host.PostAsync("/account/settings?handler=SetAgentUploads", new() { ["allowAgentUploads"] = "true" }, af);
        Assert.True(await host.AllowAgentUploadsAsync(user.Id));

        var on = await host.GetAsync("/account/settings");
        Assert.Matches("name=\"allowAgentUploads\"[^>]*checked", on.Body);
        var code = await host.UploadTokenAsync(user.Id);
        Assert.Contains($"https://files.example.com/u/{code}/llms.txt", on.Body);

        await host.PostAsync("/account/settings?handler=SetAgentUploads", new(), af);
        Assert.False(await host.AllowAgentUploadsAsync(user.Id));
        Assert.DoesNotContain("llms.txt", (await host.GetAsync("/account/settings")).Body);
    }

    [Fact]
    public async Task Agent_handlers_require_sign_in_and_a_valid_antiforgery_token()
    {
        await using var host = await Host.StartAsync();
        var user = await host.SeedUserAsync("a@example.com");
        var anonymous = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "Bot" }, null);
        Assert.NotEqual(HttpStatusCode.OK, anonymous.Status);

        await host.SignInAsync(user);
        var noToken = await host.PostAsync("/account/settings?handler=CreateAgentToken", new() { ["agentName"] = "Bot" }, null);
        Assert.Equal(HttpStatusCode.BadRequest, noToken.Status);
        Assert.Equal(0, await host.TokenCountAsync());
    }

    private sealed record Reply(HttpStatusCode Status, string Body, Dictionary<string, string> Headers);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

        private Host(WebApplication app, SqliteConnection connection)
        {
            _app = app;
            _connection = connection;
        }

        public static async Task<Host> StartAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddScoped<ApiTokenService>();
            builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", false));
            builder.Services.AddSingleton<IEmailSender>(new NoopEmailSender());
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
            builder.Services.AddRazorPages().AddApplicationPart(typeof(SettingsModel).Assembly);
            var app = builder.Build();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapRazorPages();
            app.MapGet("/test/signin/{id:guid}", async (HttpContext ctx, Guid id) =>
            {
                var db = ctx.RequestServices.GetRequiredService<AgoraDbContext>();
                var user = await db.Users.AsNoTracking().SingleAsync(x => x.Id == id);
                await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(user));
                return Results.Ok();
            });
            await app.StartAsync();
            using (var scope = app.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Database.EnsureCreatedAsync();
            }

            return new Host(app, connection);
        }

        public async Task<UserAccount> SeedUserAsync(string email)
        {
            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var user = new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = email,
                EmailConfirmed = true,
                PasswordHash = "x",
                SecurityStamp = Guid.NewGuid().ToString("N"),
                UploadToken = Guid.NewGuid().ToString("N")[..16],
                CreatedAtUtc = DateTime.UtcNow
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            return user;
        }

        public async Task<Guid> AddTokenAsync(Guid userId, string clientId, string name, string? level)
        {
            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var stamp = (await db.Users.AsNoTracking().SingleAsync(x => x.Id == userId)).SecurityStamp;
            var token = new ApiToken
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ClientId = clientId,
                DeviceName = name,
                TokenHash = ApiTokens.Hash(ApiTokens.NewToken()),
                TokenPrefix = "abcd1234",
                ExchangedAtUtc = DateTime.UtcNow,
                IssuedSecurityStamp = stamp,
                CreatedAtUtc = DateTime.UtcNow,
                AccessLevel = level
            };
            db.ApiTokens.Add(token);
            await db.SaveChangesAsync();
            return token.Id;
        }

        public async Task<ApiToken> SingleTokenAsync()
        {
            using var scope = _app.Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().ApiTokens.AsNoTracking().SingleAsync();
        }

        public async Task<int> TokenCountAsync()
        {
            using var scope = _app.Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().ApiTokens.CountAsync();
        }

        public async Task<string?> LevelAsync(Guid id)
        {
            using var scope = _app.Services.CreateScope();
            return (await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().ApiTokens.AsNoTracking().SingleAsync(x => x.Id == id)).AccessLevel;
        }

        public async Task<bool> IsRevokedAsync(Guid id)
        {
            using var scope = _app.Services.CreateScope();
            return (await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().ApiTokens.AsNoTracking().SingleAsync(x => x.Id == id)).RevokedAtUtc is not null;
        }

        public async Task RotateStampAsync(Guid userId)
        {
            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            (await db.Users.SingleAsync(x => x.Id == userId)).SecurityStamp = Guid.NewGuid().ToString("N");
            await db.SaveChangesAsync();
        }

        public async Task<bool> AllowAgentUploadsAsync(Guid userId)
        {
            using var scope = _app.Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<AuthService>().GetAllowAgentUploadsAsync(userId, CancellationToken.None);
        }

        public async Task<string> UploadTokenAsync(Guid userId)
        {
            using var scope = _app.Services.CreateScope();
            return (await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Users.AsNoTracking().SingleAsync(x => x.Id == userId)).UploadToken;
        }

        public Task SignInAsync(UserAccount user) => GetAsync($"/test/signin/{user.Id}");

        public static string? Antiforgery(string html) =>
            Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"") is { Success: true } m ? m.Groups[1].Value : null;

        public Task<Reply> GetAsync(string pathAndQuery) => SendAsync(HttpMethods.Get, pathAndQuery, null);

        public Task<Reply> PostAsync(string pathAndQuery, Dictionary<string, string> fields, string? antiforgery)
        {
            if (antiforgery is not null)
            {
                fields["__RequestVerificationToken"] = antiforgery;
            }

            return SendAsync(HttpMethods.Post, pathAndQuery, string.Join("&", fields.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}")));
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
                var pair = (setCookie ?? string.Empty).Split(';')[0].Split('=', 2);
                if (pair.Length == 2 && pair[1].Length > 0)
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

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
