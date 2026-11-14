using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Hangfire;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;

namespace Agora.Application.Tests;

/// <summary>Email sender for test hosts that only need <c>AuthService</c> to be constructible.</summary>
internal sealed class TestEmailSender : IEmailSender
{
    public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
    public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// The <c>/mcp</c> endpoint over a TestServer with the real authentication wiring, policies, rate limiter and the
/// official MCP client: challenge, caller modes, tool sets per caller, Origin check and the rate-limit rules. The
/// tool bodies are not wired to services yet; these tests only cover what does not need them.
/// </summary>
public sealed class McpHostTests
{
    private const string Base = "https://files.example.test";
    private const string MetadataUrl = Base + "/.well-known/oauth-protected-resource/mcp";
    private static readonly string[] OwnerToolNames = ["upload_file", "get_upload_url", "create_share", "get_share", "list_shares", "delete_share"];
    private const string Initialize = """{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}""";

    [Fact]
    public async Task Bare_mcp_is_challenged_with_the_resource_metadata_url_and_api_v1_stays_unchanged()
    {
        await using var host = await Host.StartAsync();

        var mcp = await host.PostMcpAsync("/mcp");
        var api = await host.SendAsync(HttpMethod.Get, "/api/v1/me");

        Assert.Equal(HttpStatusCode.Unauthorized, mcp.StatusCode);
        Assert.Equal($"Bearer resource_metadata=\"{MetadataUrl}\"", mcp.Headers.WwwAuthenticate.ToString());
        Assert.Equal("no-store", mcp.Headers.CacheControl!.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, api.StatusCode);
        Assert.Equal("Bearer", api.Headers.WwwAuthenticate.ToString());
    }

    [Theory]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("garbage")]
    public async Task Invalid_bearer_is_invalid_token_with_the_resource_metadata_url(string bearer)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp", bearer: bearer);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{MetadataUrl}\"", response.Headers.WwwAuthenticate.ToString());
    }

    [Theory]
    [InlineData("?upload=")]
    [InlineData("?upload=%20")]
    [InlineData("?upload=a&upload=b")]
    [InlineData("?other=a")]
    public async Task Missing_or_ambiguous_upload_query_without_a_bearer_is_challenged(string query)
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp" + query);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("resource_metadata", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task A_bearer_wins_over_an_upload_query()
    {
        await using var host = await Host.StartAsync();

        var response = await host.PostMcpAsync("/mcp?upload=abc", bearer: "agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Capture_token_is_forbidden()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueCaptureTokenAsync();

        var response = await host.PostMcpAsync("/mcp", bearer: token);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_caller_lists_exactly_the_two_upload_link_tools()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp?upload=Ab12cd34");

        var tools = await client.ListToolsAsync();

        Assert.Equal(["get_upload_url", "send_files"], tools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.Contains("upload link", client.ServerInstructions);
    }

    [Fact]
    public async Task Own_token_lists_the_owner_tools_without_read_share_file_and_all_adds_it()
    {
        await using var host = await Host.StartAsync();
        await using var own = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));
        await using var all = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("all"));

        var ownTools = await own.ListToolsAsync();
        var allTools = await all.ListToolsAsync();

        Assert.Equal(OwnerToolNames.Order(StringComparer.Ordinal), ownTools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.Equal(OwnerToolNames.Append("read_share_file").Order(StringComparer.Ordinal), allTools.Select(x => x.Name).Order(StringComparer.Ordinal));
        Assert.True(ownTools.Single(x => x.Name == "list_shares").ProtocolTool.Annotations!.ReadOnlyHint);
        Assert.True(ownTools.Single(x => x.Name == "delete_share").ProtocolTool.Annotations!.DestructiveHint);
    }

    [Fact]
    public async Task Access_level_changes_apply_to_the_next_session()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");
        await using (var before = await host.ConnectAsync("/mcp", token))
        {
            Assert.DoesNotContain(await before.ListToolsAsync(), x => x.Name == "read_share_file");
        }

        await host.SetLevelAsync(token, "all");

        await using var after = await host.ConnectAsync("/mcp", token);
        Assert.Contains(await after.ListToolsAsync(), x => x.Name == "read_share_file");
    }

    [Fact]
    public async Task Tools_report_that_they_are_not_available_until_wired()
    {
        await using var host = await Host.StartAsync();
        await using var client = await host.ConnectAsync("/mcp", await host.IssueAgentTokenAsync("own"));

        var result = await client.CallToolAsync("list_shares", new Dictionary<string, object?>());

        Assert.True(result.IsError);
    }

    [Fact]
    public async Task Foreign_origin_is_refused_with_a_json_rpc_error_and_no_origin_or_the_same_origin_passes()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");

        var foreign = await host.PostMcpAsync("/mcp", bearer: token, origin: "https://evil.example");
        var opaque = await host.PostMcpAsync("/mcp", bearer: token, origin: "null");
        var same = await host.PostMcpAsync("/mcp", bearer: token, origin: Base);
        var none = await host.PostMcpAsync("/mcp", bearer: token);

        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, opaque.StatusCode);
        var body = JsonDocument.Parse(await foreign.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("2.0", body.GetProperty("jsonrpc").GetString());
        Assert.False(body.TryGetProperty("id", out _));
        Assert.True(body.TryGetProperty("error", out _));
        Assert.Equal(HttpStatusCode.OK, same.StatusCode);
        Assert.Equal(HttpStatusCode.OK, none.StatusCode);
    }

    [Fact]
    public async Task Anonymous_mcp_consumes_the_public_upload_bucket_and_token_calls_do_not()
    {
        await using var host = await Host.StartAsync(limits: true);
        var token = await host.IssueAgentTokenAsync("own");

        var tokenStatuses = new List<HttpStatusCode>();
        for (var i = 0; i < 30; i++)
        {
            tokenStatuses.Add((await host.PostMcpAsync("/mcp", bearer: token)).StatusCode);
        }

        var anonymous = new List<HttpResponseMessage>();
        for (var i = 0; i < 27; i++)
        {
            anonymous.Add(await host.PostMcpAsync("/mcp?upload=Ab12cd34"));
        }

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, tokenStatuses);
        Assert.Equal(25, anonymous.Count(x => x.StatusCode != HttpStatusCode.TooManyRequests));
        Assert.Equal(2, anonymous.Count(x => x.StatusCode == HttpStatusCode.TooManyRequests));
        Assert.True(anonymous[^1].Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Anonymous_mcp_shares_its_bucket_with_the_browser_upload_routes()
    {
        await using var host = await Host.StartAsync(limits: true);
        for (var i = 0; i < 25; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/test/public-upload")).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await host.PostMcpAsync("/mcp?upload=Ab12cd34")).StatusCode);
    }

    [Fact]
    public async Task A_third_concurrent_request_per_account_is_limited_and_the_permit_is_released()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");
        var other = await host.IssueAgentTokenAsync("own");

        var first = host.StartHeldRequest(token);
        var second = host.StartHeldRequest(token);
        await host.WaitHeldAsync(2);
        var third = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        var otherAccountSameUser = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: other);
        host.ReleaseHeld();
        await Task.WhenAll(first, second);
        // The permit is returned when the middleware unwinds, which can trail the response by a moment.
        var after = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        for (var attempt = 0; attempt < 50 && after.StatusCode == HttpStatusCode.TooManyRequests; attempt++)
        {
            await Task.Delay(50);
            after = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp", bearer: token);
        }

        // Both tokens belong to one account, so the limit is per account, not per token.
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, otherAccountSameUser.StatusCode);
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
    }

    [Fact]
    public async Task Anonymous_concurrency_is_limited_per_address()
    {
        await using var host = await Host.StartAsync();

        var first = host.StartHeldRequest(null, "?upload=Ab12cd34");
        var second = host.StartHeldRequest(null, "?upload=Ab12cd34");
        await host.WaitHeldAsync(2);
        var third = await host.SendAsync(HttpMethod.Post, "/test/slow-mcp?upload=Ab12cd34");
        host.ReleaseHeld();
        await Task.WhenAll(first, second);

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public async Task Request_body_limit_of_2_MiB_applies_to_mcp()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueAgentTokenAsync("own");

        var tooLarge = await host.PostMcpAsync("/mcp", bearer: token, body: new string('a', 2 * 1024 * 1024 + 1));

        Assert.True(tooLarge.StatusCode is HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.BadRequest, tooLarge.StatusCode.ToString());
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly HttpClient _client;
        private readonly string _storageRoot;
        private readonly Guid _userId;
        private readonly string _stamp;
        private readonly SemaphoreSlim _held = new(0);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private Host(WebApplication app, SqliteConnection connection, string storageRoot, Guid userId, string stamp)
        {
            _app = app;
            _connection = connection;
            _storageRoot = storageRoot;
            _userId = userId;
            _stamp = stamp;
            _client = app.GetTestClient();
        }

        public static async Task<Host> StartAsync(bool limits = false)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-mcp-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var holder = new HeldRequests();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o => o.StorageRoot = storageRoot);
            builder.Services.AddSingleton<UploadConcurrency>();
            builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient>(new NoJobs());
            builder.Services.AddSingleton<KeyedAsyncLock>();
            var scratchOptions = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = 0, MinFreeBytes = 0 } };
            builder.Services.AddSingleton(new ScratchSpaceMonitor(scratchOptions, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
            builder.Services.AddSingleton<IPublicOriginProvider>(new FixedOrigin());
            builder.Services.AddScoped<Agora.Infrastructure.Services.ShareManager>();
            builder.Services.AddSingleton<IEmailSender, TestEmailSender>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddScoped<ApiTokenService>();
            builder.Services.AddSingleton(new PublicBaseUrlResolver(Base, allowRequestHostFallback: false));
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAgoraAuthentication(new AgoraAuthOptions(), CookieSecurePolicy.None);
            builder.Services.AddAuthorization(AuthSetup.ConfigureAuthorization);
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions { AnonymousPerMinute = 0 }, isE2E: !limits));
            builder.Services.AddAgoraAgents();

            var app = builder.Build();
            app.UseAgoraExceptionHandler();
            app.UseAuthentication();
            app.UseRateLimiter();
            app.UseAuthorization();
            app.MapGet("/test/public-upload", () => "ok").RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);
            app.MapApiV1Endpoints(captureRequestBodyLimit: 1024 * 1024);
            app.MapAgoraAgents();
            // Stands in for a slow /mcp call: same metadata, policy and limiters, held until released.
            app.MapPost("/test/slow-mcp", async (HttpContext context) =>
            {
                holder.Held.Release();
                await holder.Release.Task.WaitAsync(context.RequestAborted);
                return Results.Ok();
            }).WithMetadata(ApiEndpointMetadata.Instance, McpEndpointMetadata.Instance)
              .RequireAuthorization(ApiTokenDefaults.AgentMcpPolicy)
              .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);
            await app.StartAsync();

            var user = TestUsers.Seed(Guid.NewGuid(), "owner@example.com");
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(user);
                await db.SaveChangesAsync();
            }

            var host = new Host(app, connection, storageRoot, user.Id, user.SecurityStamp);
            host._heldHolder = holder;
            return host;
        }

        private HeldRequests? _heldHolder;

        public Task<HttpResponseMessage> StartHeldRequest(string? bearer, string query = "") =>
            SendAsync(HttpMethod.Post, "/test/slow-mcp" + query, bearer);

        public async Task WaitHeldAsync(int count)
        {
            for (var i = 0; i < count; i++)
            {
                Assert.True(await _heldHolder!.Held.WaitAsync(TimeSpan.FromSeconds(10)));
            }
        }

        public void ReleaseHeld() => _heldHolder!.Release.TrySetResult();

        public async Task<string> IssueAgentTokenAsync(string level)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return (await scope.ServiceProvider.GetRequiredService<ApiTokenService>()
                .CreateAgentTokenAsync(_userId, _stamp, "Test agent", level, CancellationToken.None))!;
        }

        public async Task<string> IssueCaptureTokenAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ApiTokenService>();
            var code = (await tokens.CreatePendingAsync(_userId, _stamp, ApiTokens.CaptureClientId, "Mac", ApiTokenServiceTests.Challenge, ApiTokenServiceTests.Redirect, CancellationToken.None))!;
            return (await tokens.ExchangeAsync(code, ApiTokenServiceTests.Verifier, ApiTokenServiceTests.Redirect, ApiTokens.CaptureClientId, CancellationToken.None)).AccessToken!;
        }

        public async Task SetLevelAsync(string token, string level)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ApiTokenService>();
            var identity = (await tokens.ValidateAsync(token, CancellationToken.None))!;
            Assert.True(await tokens.SetAccessLevelAsync(identity.TokenId, _userId, level, CancellationToken.None));
        }

        public async Task<McpClient> ConnectAsync(string path, string? bearer = null)
        {
            var http = _app.GetTestClient();
            if (bearer is not null)
            {
                http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            var transport = new HttpClientTransport(new HttpClientTransportOptions { Endpoint = new Uri(Base + path) }, http, ownsHttpClient: true);
            return await McpClient.CreateAsync(transport);
        }

        public Task<HttpResponseMessage> PostMcpAsync(string path, string? bearer = null, string? origin = null, string? body = null) =>
            SendAsync(HttpMethod.Post, path, bearer, origin, new StringContent(body ?? Initialize, Encoding.UTF8, "application/json"), mcp: true);

        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? bearer = null, string? origin = null, HttpContent? content = null, bool mcp = false)
        {
            using var request = new HttpRequestMessage(method, path) { Content = content };
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            if (origin is not null)
            {
                request.Headers.Add("Origin", origin);
            }

            if (mcp)
            {
                request.Headers.Accept.ParseAdd("application/json");
                request.Headers.Accept.ParseAdd("text/event-stream");
            }

            return await _client.SendAsync(request);
        }

        public async ValueTask DisposeAsync()
        {
            _heldHolder?.Release.TrySetResult();
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class HeldRequests
    {
        public SemaphoreSlim Held { get; } = new(0);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class NoJobs : IBackgroundJobClient
    {
        public string Create(Hangfire.Common.Job job, Hangfire.States.IState state) => "1";

        public bool ChangeState(string jobId, Hangfire.States.IState state, string expectedState) => true;
    }

    private sealed class FixedOrigin : IPublicOriginProvider
    {
        public string? ConfiguredOrigin => Base;
    }
}
