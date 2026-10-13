using System.Net;
using System.Text;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Endpoints;
using Agora.Web.Startup;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Agora.Application.Tests;

/// <summary>
/// Runs the real staging endpoints and CSRF middleware in a TestServer: admission and the multipart-buffer
/// reservation must happen before a request body is read, keyed on endpoint metadata rather than on the path.
/// </summary>
public sealed class UploadStagingEndpointTests
{
    private const string Owner = "owner@example.com";
    private const string UploadCode = "code1";

    [Fact]
    public async Task Stage_without_header_token_is_refused_before_the_body_is_read_even_with_a_trailing_slash()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = new ThrowingStream();

        var context = await host.PostStageAsync("/api/public-uploads/stage/", body, contentLength: 100, csrf: host.Csrf with { HeaderToken = null });

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Stage_with_header_token_succeeds_and_stages_the_file()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = Host.MultipartBody("hello");

        var context = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), body.Length, host.Csrf);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Single(Directory.EnumerateDirectories(Path.Combine(host.StorageRoot, "uploads", "staged")));
    }

    [Fact]
    public async Task Stage_without_content_length_reserves_the_endpoint_body_limit_not_the_file_maximum()
    {
        // Endpoint limit is 10 MiB (see MapUploadStagingEndpoints below) while MaxFileSizeBytes defaults to gigabytes:
        // a chunked body must reserve the former, so it fits a 50 MiB scratch budget instead of answering 507.
        await using var host = await Host.StartAsync(scratchMaxBytes: 50L * 1024 * 1024);
        var body = Host.MultipartBody("hello");

        var context = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), contentLength: null, host.Csrf);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Single(Directory.EnumerateDirectories(Path.Combine(host.StorageRoot, "uploads", "staged")));
    }

    [Fact]
    public async Task Second_concurrent_stage_gets_507_before_buffering_when_only_one_fits()
    {
        var body = Host.MultipartBody("hello");
        await using var host = await Host.StartAsync(scratchMaxBytes: body.Length + body.Length / 2);
        var first = new GateStream(body);

        // The first request holds the buffer reservation while its body is still streaming in.
        var firstRequest = host.PostStageAsync("/api/public-uploads/stage", first, body.Length, host.Csrf);
        await first.Started.Task;

        var second = new ThrowingStream();
        var secondContext = await host.PostStageAsync("/api/public-uploads/stage", second, body.Length, host.Csrf);
        Assert.Equal(StatusCodes.Status507InsufficientStorage, secondContext.Response.StatusCode);
        Assert.False(second.ReadAttempted);

        first.Release();
        var firstContext = await firstRequest;
        Assert.Equal(StatusCodes.Status200OK, firstContext.Response.StatusCode);

        // The buffer reservation is released by the response's dispose callbacks, which run after the pipeline returns.
        for (var i = 0; i < 100 && host.Scratch.Reserved != (0L, 0L); i++)
        {
            await Task.Delay(20);
        }

        Assert.Equal((0L, 0L), host.Scratch.Reserved);
    }

    private sealed record CsrfTokens(string CookieHeader, string? HeaderToken);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;

        public string StorageRoot { get; }
        public ScratchSpaceMonitor Scratch { get; }
        public CsrfTokens Csrf { get; private set; } = new(string.Empty, null);

        private Host(WebApplication app, SqliteConnection connection, string storageRoot, ScratchSpaceMonitor scratch)
        {
            _app = app;
            _connection = connection;
            StorageRoot = storageRoot;
            Scratch = scratch;
        }

        public static async Task<Host> StartAsync(long scratchMaxBytes)
        {
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-stage-endpoint-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = scratchMaxBytes, MinFreeBytes = 0 } };
            var scratch = new ScratchSpaceMonitor(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o =>
            {
                o.StorageRoot = storageRoot;
                o.Scratch = options.Scratch;
            });
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient, NoopBackgroundJobClient>();
            builder.Services.AddSingleton<IEmailSender, NoopEmailSender>();
            builder.Services.AddSingleton<KeyedAsyncLock>();
            builder.Services.AddSingleton(scratch);
            builder.Services.AddScoped<ShareManager>();
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddAntiforgery(o =>
            {
                o.Cookie.Name = "agora.csrf";
                o.FormFieldName = "__RequestVerificationToken";
                o.HeaderName = CsrfValidation.HeaderName;
            });
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions(), isE2E: true));

            var app = builder.Build();
            app.UseAgoraCsrf(isE2E: false, CookieSecurePolicy.None, NullLogger.Instance);
            app.UseRateLimiter();
            app.MapGet("/", () => Results.Ok());
            app.MapUploadStagingEndpoints(stageRequestBodyLimit: 10 * 1024 * 1024);
            await app.StartAsync();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(new UserAccount
                {
                    Id = Guid.NewGuid(),
                    Email = Owner,
                    EmailConfirmed = true,
                    PasswordHash = "x",
                    UploadToken = UploadCode,
                    IsEnabled = true,
                    CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }

            var host = new Host(app, connection, storageRoot, scratch);
            await host.FetchCsrfAsync();
            return host;
        }

        private async Task FetchCsrfAsync()
        {
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = "/";
            });

            var cookies = context.Response.Headers.SetCookie
                .Select(value => (value ?? string.Empty).Split(';')[0])
                .ToList();
            var requestToken = cookies
                .Select(pair => pair.Split('=', 2))
                .Single(parts => parts[0] == CsrfValidation.RequestTokenCookieName)[1];
            Csrf = new CsrfTokens(string.Join("; ", cookies), Uri.UnescapeDataString(requestToken));
        }

        public static byte[] MultipartBody(string content) => Encoding.ASCII.GetBytes(
            "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n" +
            content + "\r\n--b--\r\n");

        public Task<HttpContext> PostStageAsync(string path, Stream body, long? contentLength, CsrfTokens csrf)
        {
            return _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Post;
                ctx.Request.Path = path;
                ctx.Request.QueryString = new QueryString($"?uploadToken={UploadCode}&draftShareId={Guid.NewGuid():N}");
                ctx.Request.ContentType = "multipart/form-data; boundary=b";
                ctx.Request.ContentLength = contentLength;
                ctx.Request.Body = body;
                ctx.Request.Headers.Cookie = csrf.CookieHeader;
                if (csrf.HeaderToken is not null)
                {
                    ctx.Request.Headers[CsrfValidation.HeaderName] = csrf.HeaderToken;
                }
            });
        }

        public async ValueTask DisposeAsync()
        {
            await _app.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(StorageRoot))
            {
                Directory.Delete(StorageRoot, recursive: true);
            }
        }
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<string> RenderDownloadNotificationHtmlAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.FromResult(string.Empty);

        public Task<string> RenderAuthEmailHtmlAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }
}
