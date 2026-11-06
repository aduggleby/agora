using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Startup;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
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
using Microsoft.Extensions.Logging.Abstractions;

namespace Agora.Application.Tests;

/// <summary>
/// Runs the real authentication/authorization wiring (<see cref="AuthSetup"/>), CSRF middleware and the
/// <c>/api/v1</c> endpoints over a TestServer. Covers the credential invariants: API tokens work only on
/// <c>/api/v1</c>, cookies never work there, a token never gets a login redirect, and the capture/delete endpoints
/// behave like the browser direct-link flow.
/// </summary>
public sealed class ApiV1HostTests
{
    private const string Email = "owner@example.com";

    [Fact]
    public async Task Bearer_token_reaches_me_and_gets_no_csrf_cookies()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();

        var response = await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(Email, body.GetProperty("email").GetString());
        Assert.Equal(["30m", "6h", "1d", "7d"], body.GetProperty("directLinkDurations").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(AppVersion.Current, body.GetProperty("serverVersion").GetString());
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Cookie_is_not_accepted_on_api_v1()
    {
        await using var host = await Host.StartAsync();
        var cookie = await host.LoginCookieAsync();

        var response = await host.SendAsync(HttpMethod.Get, "/api/v1/me", cookie: cookie);

        await AssertBearerChallengeAsync(response);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    public async Task Missing_or_unknown_token_gets_a_json_401(string? token)
    {
        await using var host = await Host.StartAsync();

        var response = await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: token);

        await AssertBearerChallengeAsync(response);
        if (token is not null)
        {
            Assert.Contains("invalid_token", response.Headers.WwwAuthenticate.ToString());
        }
    }

    [Theory]
    [InlineData("/cookie-only")]
    [InlineData("/admin-only")]
    public async Task Bearer_token_is_refused_by_cookie_endpoints_without_a_login_redirect(string path)
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();

        var response = await host.SendAsync(HttpMethod.Get, path, bearer: token);

        await AssertBearerChallengeAsync(response);
    }

    [Fact]
    public async Task Bearer_post_to_a_cookie_endpoint_gets_a_json_401_not_a_csrf_error()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();

        var response = await host.SendAsync(HttpMethod.Post, "/cookie-only", bearer: token, content: new StringContent("x"));

        await AssertBearerChallengeAsync(response);
    }

    [Fact]
    public async Task Browser_without_cookie_is_redirected_to_login_with_return_url()
    {
        await using var host = await Host.StartAsync();

        var response = await host.SendAsync(HttpMethod.Get, "/cookie-only?x=1");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/login?returnUrl=%2Fcookie-only%3Fx%3D1", response.Headers.Location!.PathAndQuery);
    }

    [Fact]
    public async Task Anonymous_post_to_a_signed_in_endpoint_is_challenged_before_the_body_is_read()
    {
        await using var host = await Host.StartAsync();
        var body = new ThrowingStream();

        var context = await host.PostRawMultipartAsync("/cookie-only", string.Empty, body, bearer: null, cookie: null, contentLength: 50L * 1024 * 1024);

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Contains("/login?returnUrl=", context.Response.Headers.Location.ToString());
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Post_to_an_unmatched_route_is_404_without_reading_the_body()
    {
        await using var host = await Host.StartAsync();
        var body = new ThrowingStream();

        var context = await host.PostRawMultipartAsync("/does-not-exist", string.Empty, body, bearer: null, cookie: null, contentLength: 50L * 1024 * 1024);

        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Anonymous_form_post_stops_reading_at_the_app_wide_form_limit()
    {
        await using var host = await Host.StartAsync();
        var payload = MultipartFile("big.bin", new byte[3 * 1024 * 1024]);
        var body = new CountingStream(payload);

        var context = await host.PostRawMultipartAsync("/anonymous-form", string.Empty, body, bearer: null, cookie: null, contentLength: payload.Length);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        // The antiforgery form fallback gives up at the 1 MiB section limit (plus one read buffer), not at 3 MiB.
        Assert.True(body.BytesRead < FormLimits.DefaultMaxRequestBodyBytes + 128 * 1024, $"read {body.BytesRead} bytes");
    }

    [Fact]
    public async Task Capture_larger_than_the_app_wide_form_limit_still_succeeds()
    {
        await using var host = await Host.StartAsync(maxFileSizeBytes: 4L * 1024 * 1024);
        var token = await host.IssueTokenAsync();

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=1d", bearer: token,
            content: Multipart("capture.png", PaddedPng(2 * 1024 * 1024)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static byte[] MultipartFile(string fileName, byte[] content) =>
    [
        .. Encoding.ASCII.GetBytes($"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fileName}\"\r\nContent-Type: application/octet-stream\r\n\r\n"),
        .. content,
        .. Encoding.ASCII.GetBytes("\r\n--b--\r\n")
    ];

    [Fact]
    public async Task Bearer_token_is_ignored_outside_api_v1()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();
        var cookie = await host.LoginCookieAsync();

        // Anonymous endpoint: the token does not produce a principal.
        var anonymous = await host.SendAsync(HttpMethod.Get, "/whoami", bearer: token);
        Assert.Equal("anonymous", await anonymous.Content.ReadAsStringAsync());

        // With both credentials a cookie endpoint sees the cookie principal only.
        var both = await host.SendAsync(HttpMethod.Get, "/cookie-only", bearer: token, cookie: cookie);
        Assert.Equal(HttpStatusCode.OK, both.StatusCode);
        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, await both.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Api_token_principal_is_never_reissued_as_a_cookie()
    {
        var context = new DefaultHttpContext
        {
            User = ApiTokenDefaults.CreatePrincipal(new ApiTokenIdentity(Guid.NewGuid(), Guid.NewGuid(), Email, "Owner"))
        };

        // No services are registered: reaching SignIn/SignOut or the database would throw.
        Assert.False(await CookieSessions.TryReissueAsync(context, null!, CancellationToken.None));
        Assert.False(CookieSessions.IsCookiePrincipal(context.User));
        Assert.Null(context.User.FindFirstValue(ClaimTypes.Role));
        Assert.Null(context.User.FindFirstValue(CookieSessions.SecurityStampClaim));
    }

    [Fact]
    public async Task Token_endpoint_exchanges_once_and_answers_rfc6749_errors()
    {
        await using var host = await Host.StartAsync();
        var code = await host.CodeAsync();
        var request = new
        {
            grant_type = "authorization_code",
            code,
            code_verifier = ApiTokenServiceTests.Verifier,
            redirect_uri = ApiTokenServiceTests.Redirect,
            client_id = ApiTokens.CaptureClientId
        };

        var ok = await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(request));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains("no-store", ok.Headers.CacheControl!.ToString());
        var body = await ok.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(Email, body.GetProperty("email").GetString());
        var token = body.GetProperty("access_token").GetString();
        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: token)).StatusCode);

        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(request)), "invalid_grant");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token",
            content: new StringContent("{not json", Encoding.UTF8, "application/json")), "invalid_request");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token",
            content: JsonContent.Create(new { grant_type = "password", code })), "unsupported_grant_type");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token",
            content: JsonContent.Create(new { grant_type = "authorization_code" })), "invalid_request");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token",
            content: new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "authorization_code" })), "invalid_request");
    }

    [Fact]
    public async Task Token_requests_refused_before_the_code_check_do_not_burn_the_code()
    {
        await using var host = await Host.StartAsync();
        var code = await host.CodeAsync();
        object Body(string grantType = "authorization_code", string clientId = ApiTokens.CaptureClientId, string? verifier = ApiTokenServiceTests.Verifier) => new
        {
            grant_type = grantType,
            code,
            code_verifier = verifier,
            redirect_uri = ApiTokenServiceTests.Redirect,
            client_id = clientId
        };

        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(Body(verifier: null))), "invalid_request");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(Body(clientId: "other-app"))), "invalid_request");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(Body(grantType: "refresh_token"))), "unsupported_grant_type");
        await AssertTokenErrorAsync(await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token",
            content: new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["code"] = code })), "invalid_request");

        Assert.Equal(HttpStatusCode.OK, (await host.SendAsync(HttpMethod.Post, "/api/v1/auth/token", content: JsonContent.Create(Body()))).StatusCode);
    }

    [Fact]
    public async Task Failed_api_authentication_is_throttled_by_the_anonymous_rate_limit()
    {
        await using var host = await Host.StartAsync(anonymousPerMinute: 2);
        const string unknown = "agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: unknown)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=1d", bearer: unknown)).StatusCode);
        var throttled = await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: unknown);

        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);
    }

    [Fact]
    public async Task Delete_share_retry_after_a_failed_enqueue_queues_the_file_cleanup()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();
        var shareToken = await host.SeedShareAsync(host.UserId, ShareAccessMode.DirectLink);

        host.Jobs.Fail = true;
        var failed = await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{shareToken}", bearer: token);
        Assert.Equal(HttpStatusCode.InternalServerError, failed.StatusCode);
        Assert.NotNull((await host.ShareAsync(shareToken)).DeletedAtUtc);
        Assert.Empty(host.Jobs.Jobs);

        host.Jobs.Fail = false;
        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{shareToken}", bearer: token)).StatusCode);
        var job = Assert.Single(host.Jobs.Jobs);
        Assert.Equal(nameof(ShareManager.DeleteShareFilesAsync), job.Method.Name);
    }

    [Fact]
    public async Task Delete_auth_token_revokes_the_calling_token()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();

        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, "/api/v1/auth/token", bearer: token)).StatusCode);

        await AssertBearerChallengeAsync(await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: token));
    }

    [Fact]
    public async Task Cookie_post_to_captures_is_refused_before_the_body_is_read()
    {
        await using var host = await Host.StartAsync();
        var cookie = await host.LoginCookieAsync();
        var body = new ThrowingStream();

        var context = await host.PostRawMultipartAsync("/api/v1/captures", "?duration=1d", body, bearer: null, cookie: cookie);

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Capture_creates_a_direct_link_and_delete_removes_it()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=30m", bearer: token,
            content: Multipart("capture.png", PngCrafting.HeaderOnly(4, 4)));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var shareToken = body.GetProperty("token").GetString()!;
        Assert.Equal($"https://files.example.test/s/{shareToken}", body.GetProperty("url").GetString());
        var share = await host.ShareAsync(shareToken);
        Assert.True(ShareModes.IsDirectLink(share.AccessMode));
        Assert.Equal("capture.png", share.ZipDisplayName);
        Assert.InRange(share.ExpiresAtUtc!.Value, DateTime.UtcNow.AddMinutes(29), DateTime.UtcNow.AddMinutes(31));
        Assert.Empty(host.ScratchEntries());

        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{shareToken}", bearer: token)).StatusCode);
        Assert.NotNull((await host.ShareAsync(shareToken)).DeletedAtUtc);
        Assert.Equal(HttpStatusCode.NoContent, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{shareToken}", bearer: token)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{shareToken.ToUpperInvariant()}x", bearer: token)).StatusCode);
    }

    [Fact]
    public async Task Delete_share_is_404_for_other_owners_and_normal_shares()
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();
        var foreign = await host.SeedShareAsync(Guid.NewGuid(), ShareAccessMode.DirectLink);
        var normal = await host.SeedShareAsync(host.UserId, ShareAccessMode.DownloadOnly);

        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{foreign}", bearer: token)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(HttpMethod.Delete, $"/api/v1/shares/{normal}", bearer: token)).StatusCode);
        Assert.Null((await host.ShareAsync(foreign)).DeletedAtUtc);
        Assert.Null((await host.ShareAsync(normal)).DeletedAtUtc);
    }

    [Theory]
    [InlineData(1000L, 1000L)] // equal limits
    [InlineData(5000L, 1000L)] // smaller per-share total
    public async Task Capture_over_the_effective_limit_is_413_not_a_multipart_error(long maxFile, long maxTotal)
    {
        await using var host = await Host.StartAsync(maxFileSizeBytes: maxFile, maxTotalUploadBytes: maxTotal);
        var token = await host.IssueTokenAsync();

        var tooLarge = await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=1d", bearer: token,
            content: Multipart("capture.png", PaddedPng(2000)));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);
        Assert.Equal(UploadStagingEndpoints.TooLargeMessage, (await tooLarge.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetString());
        Assert.Empty(host.ScratchEntries());

        var fits = await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=1d", bearer: token,
            content: Multipart("capture.png", PaddedPng(500)));
        Assert.Equal(HttpStatusCode.OK, fits.StatusCode);

        var me = await (await host.SendAsync(HttpMethod.Get, "/api/v1/me", bearer: token)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(Math.Min(maxFile, maxTotal), me.GetProperty("maxFileSizeBytes").GetInt64());
    }

    private static byte[] PaddedPng(int length)
    {
        var bytes = new byte[length];
        PngCrafting.HeaderOnly(4, 4).CopyTo(bytes, 0);
        return bytes;
    }

    [Theory]
    [InlineData("capture.txt", false)]
    [InlineData("capture.png", true)]
    public async Task Capture_refuses_non_images_and_leaves_no_draft(string fileName, bool lieAboutType)
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();
        var payload = lieAboutType ? Encoding.ASCII.GetBytes("<html>not a png</html>") : Encoding.ASCII.GetBytes("hello");

        var response = await host.SendAsync(HttpMethod.Post, "/api/v1/captures?duration=1d", bearer: token, content: Multipart(fileName, payload));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(host.ScratchEntries());
        Assert.Equal(0, await host.ShareCountAsync());
    }

    [Theory]
    [InlineData("")]
    [InlineData("?duration=2d")]
    public async Task Capture_refuses_a_bad_duration_before_reading_the_body(string query)
    {
        await using var host = await Host.StartAsync();
        var token = await host.IssueTokenAsync();
        var body = new ThrowingStream();

        var context = await host.PostRawMultipartAsync("/api/v1/captures", query, body, bearer: token, cookie: null);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
    }

    private static async Task AssertBearerChallengeAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.StartsWith("Bearer", response.Headers.WwwAuthenticate.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(string.IsNullOrEmpty(body.GetProperty("error").GetString()));
    }

    private static async Task AssertTokenErrorAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(error, body.GetProperty("error").GetString());
        Assert.True(body.TryGetProperty("error_description", out _));
    }

    private static MultipartFormDataContent Multipart(string fileName, byte[] payload)
    {
        var content = new MultipartFormDataContent();
        var file = new ByteArrayContent(payload);
        file.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        content.Add(file, "file", fileName);
        return content;
    }

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly HttpClient _client;
        private readonly string _storageRoot;

        public Guid UserId { get; }
        public string Stamp { get; }
        public RecordingJobClient Jobs { get; }

        private Host(WebApplication app, SqliteConnection connection, string storageRoot, Guid userId, string stamp, RecordingJobClient jobs)
        {
            _app = app;
            _connection = connection;
            _storageRoot = storageRoot;
            _client = app.GetTestClient();
            UserId = userId;
            Stamp = stamp;
            Jobs = jobs;
        }

        public static async Task<Host> StartAsync(int? anonymousPerMinute = null, long? maxFileSizeBytes = null, long? maxTotalUploadBytes = null)
        {
            var jobs = new RecordingJobClient();
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-api-v1-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = 0, MinFreeBytes = 0 } };
            var scratch = new ScratchSpaceMonitor(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o =>
            {
                o.StorageRoot = storageRoot;
                o.Scratch = options.Scratch;
                o.MaxFileSizeBytes = maxFileSizeBytes ?? o.MaxFileSizeBytes;
                o.MaxTotalUploadBytes = maxTotalUploadBytes ?? o.MaxTotalUploadBytes;
            });
            // As in Program.cs: small app-wide form limits; upload endpoints pass their own per call.
            builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(FormLimits.Configure);
            builder.Services.AddSingleton<UploadConcurrency>();
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient>(jobs);
            builder.Services.AddSingleton<KeyedAsyncLock>();
            builder.Services.AddSingleton(scratch);
            builder.Services.AddSingleton<IPublicOriginProvider>(new FixedOrigin());
            builder.Services.AddScoped<ShareManager>();
            builder.Services.AddScoped<ApiTokenService>();
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAgoraAuthentication(new AgoraAuthOptions(), CookieSecurePolicy.None);
            builder.Services.AddAuthorization(AuthSetup.ConfigureAuthorization);
            builder.Services.AddAntiforgery(o =>
            {
                o.Cookie.Name = "agora.csrf";
                o.HeaderName = CsrfValidation.HeaderName;
            });
            // Anonymous throttling is off (E2E mode) unless a test asks for a budget.
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(
                o,
                new AgoraRateLimitOptions { AnonymousPerMinute = anonymousPerMinute ?? 0 },
                isE2E: anonymousPerMinute is null));

            var app = builder.Build();
            app.UseAgoraExceptionHandler();
            app.UseAuthentication();
            app.UseAgoraCsrf(isE2E: false, CookieSecurePolicy.None, NullLogger.Instance);
            app.UseRateLimiter();
            app.UseAuthorization();
            // Test-only sign-in (GET, so CSRF does not apply).
            app.MapGet("/test/login", async (HttpContext context, AgoraDbContext db) =>
            {
                var user = await db.Users.SingleAsync(x => x.Email == Email);
                await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CookieSessions.CreatePrincipal(user));
                return Results.Ok();
            });
            app.MapGet("/whoami", (HttpContext context) => context.User.Identity?.AuthenticationType ?? "anonymous");
            app.MapGet("/cookie-only", (HttpContext context) => context.User.Identity!.AuthenticationType).RequireAuthorization();
            app.MapGet("/admin-only", () => "admin").RequireAuthorization(AuthSetup.AdminOnlyPolicy);
            app.MapPost("/cookie-only", () => "posted").RequireAuthorization();
            // Stands in for anonymous form endpoints such as /login: antiforgery reads the form when no header token is sent.
            app.MapPost("/anonymous-form", () => "posted");
            app.MapApiV1Endpoints(captureRequestBodyLimit: maxFileSizeBytes is { } maxFile ? maxFile + 1024 * 1024 : 10 * 1024 * 1024);
            await app.StartAsync();

            var user = TestUsers.Seed(Guid.NewGuid(), Email);
            user.Role = "admin";
            await using (var scope = app.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(user);
                await db.SaveChangesAsync();
            }

            return new Host(app, connection, storageRoot, user.Id, user.SecurityStamp, jobs);
        }

        public async Task<string> CodeAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            var tokens = scope.ServiceProvider.GetRequiredService<ApiTokenService>();
            return (await tokens.CreatePendingAsync(UserId, Stamp, ApiTokens.CaptureClientId, "Test Mac", ApiTokenServiceTests.Challenge, ApiTokenServiceTests.Redirect, CancellationToken.None))!;
        }

        public async Task<string> IssueTokenAsync()
        {
            var code = await CodeAsync();
            await using var scope = _app.Services.CreateAsyncScope();
            var result = await scope.ServiceProvider.GetRequiredService<ApiTokenService>()
                .ExchangeAsync(code, ApiTokenServiceTests.Verifier, ApiTokenServiceTests.Redirect, ApiTokens.CaptureClientId, CancellationToken.None);
            return result.AccessToken!;
        }

        public async Task<string> LoginCookieAsync()
        {
            var response = await _client.GetAsync("/test/login");
            return string.Join("; ", response.Headers.GetValues("Set-Cookie").Select(x => x.Split(';')[0]));
        }

        public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? bearer = null, string? cookie = null, HttpContent? content = null)
        {
            using var request = new HttpRequestMessage(method, path) { Content = content };
            if (bearer is not null)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            }

            if (cookie is not null)
            {
                request.Headers.Add("Cookie", cookie);
            }

            return await _client.SendAsync(request);
        }

        /// <summary>A multipart POST whose body stream is handed to the server untouched (HttpClient would read it first).</summary>
        public Task<HttpContext> PostRawMultipartAsync(string path, string query, Stream body, string? bearer, string? cookie, long contentLength = 100) =>
            _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Post;
                ctx.Request.Path = path;
                ctx.Request.QueryString = new QueryString(query);
                ctx.Request.ContentType = "multipart/form-data; boundary=b";
                ctx.Request.ContentLength = contentLength;
                ctx.Request.Body = body;
                if (bearer is not null)
                {
                    ctx.Request.Headers.Authorization = $"Bearer {bearer}";
                }

                if (cookie is not null)
                {
                    ctx.Request.Headers.Cookie = cookie;
                }
            });

        public async Task<Share> ShareAsync(string token)
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Shares.AsNoTracking().SingleAsync(x => x.ShareToken == token);
        }

        public async Task<int> ShareCountAsync()
        {
            await using var scope = _app.Services.CreateAsyncScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Shares.CountAsync();
        }

        public async Task<string> SeedShareAsync(Guid ownerUserId, ShareAccessMode mode)
        {
            var token = TokenCodec.GenerateAlphanumericToken(10);
            await using var scope = _app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerUserId,
                UploaderEmail = "someone@example.com",
                ShareToken = token,
                ZipDisplayName = "a.png",
                AccessMode = ShareModes.ToStorageValue(mode),
                ShareExperienceType = ShareModes.ToStorageValue(ShareExperienceType.Archive),
                NotifyMode = "none",
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            });
            await db.SaveChangesAsync();
            return token;
        }

        /// <summary>Everything left under the staging and draft roots (empty directories excluded).</summary>
        public IReadOnlyList<string> ScratchEntries() =>
            new[] { "staged", "drafts" }
                .Select(dir => Path.Combine(_storageRoot, "uploads", dir))
                .Where(Directory.Exists)
                .SelectMany(dir => Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                .ToList();

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class FixedOrigin : IPublicOriginProvider
    {
        public string? ConfiguredOrigin => "https://files.example.test";
    }

    /// <summary>Records enqueued jobs; <see cref="Fail"/> makes the next enqueues throw, like an unreachable Hangfire store.</summary>
    private sealed class RecordingJobClient : IBackgroundJobClient
    {
        public bool Fail { get; set; }
        public List<Job> Jobs { get; } = [];

        public string Create(Job job, IState state)
        {
            if (Fail)
            {
                throw new InvalidOperationException("Hangfire storage unavailable.");
            }

            Jobs.Add(job);
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
