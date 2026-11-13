using System.Net;
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
using Agora.Web.Endpoints;
using Agora.Web.Services;
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
using SkiaSharp;

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
        try
        {
            await host.WaitUntilReadingAsync(first, firstRequest);

            var second = new ThrowingStream();
            var secondContext = await host.PostStageAsync("/api/public-uploads/stage", second, body.Length, host.Csrf).WaitAsync(Host.Timeout);
            Assert.Equal(StatusCodes.Status507InsufficientStorage, secondContext.Response.StatusCode);
            Assert.False(second.ReadAttempted);
        }
        finally
        {
            first.Release();
        }

        var firstContext = await firstRequest.WaitAsync(Host.Timeout);
        Assert.Equal(StatusCodes.Status200OK, firstContext.Response.StatusCode);

        // The buffer reservation is released by the response's dispose callbacks, which run after the pipeline returns.
        for (var i = 0; i < 100 && host.Scratch.Reserved != (0L, 0L); i++)
        {
            await Task.Delay(20);
        }

        Assert.Equal((0L, 0L), host.Scratch.Reserved);
    }

    [Fact]
    public async Task Third_concurrent_stage_from_one_address_gets_429_before_the_body_is_read()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = Host.MultipartBody("hello");
        var first = new GateStream(body);
        var second = new GateStream(body);
        // One at a time up to the gate: the test host shares one in-memory SQLite connection, which must not be used
        // by two requests at once (production uses a pooled database).
        var firstRequest = host.PostStageAsync("/api/public-uploads/stage", first, body.Length, host.Csrf);
        Task<HttpContext>? secondRequest = null;
        try
        {
            await host.WaitUntilReadingAsync(first, firstRequest);
            secondRequest = host.PostStageAsync("/api/public-uploads/stage", second, body.Length, host.Csrf);
            await host.WaitUntilReadingAsync(second, secondRequest);

            var third = new ThrowingStream();
            var thirdContext = await host.PostStageAsync("/api/public-uploads/stage", third, body.Length, host.Csrf).WaitAsync(Host.Timeout);
            Assert.Equal(StatusCodes.Status429TooManyRequests, thirdContext.Response.StatusCode);
            Assert.False(third.ReadAttempted);

            // Another address is not affected.
            var other = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), body.Length, host.Csrf, remoteIp: "198.51.100.7").WaitAsync(Host.Timeout);
            Assert.Equal(StatusCodes.Status200OK, other.Response.StatusCode);
        }
        finally
        {
            first.Release();
            second.Release();
        }

        Assert.Equal(StatusCodes.Status200OK, (await firstRequest.WaitAsync(Host.Timeout)).Response.StatusCode);
        Assert.Equal(StatusCodes.Status200OK, (await secondRequest!.WaitAsync(Host.Timeout)).Response.StatusCode);
        await host.WaitForNoUploadsInFlightAsync("addr:203.0.113.1");

        var afterwards = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), body.Length, host.Csrf);
        Assert.Equal(StatusCodes.Status200OK, afterwards.Response.StatusCode);
    }

    [Fact]
    public async Task Third_concurrent_stage_into_one_draft_gets_429_from_any_address()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = Host.MultipartBody("hello");
        var draft = Guid.NewGuid().ToString("N");
        var first = new GateStream(body);
        var second = new GateStream(body);
        // One at a time up to the gate (shared in-memory SQLite connection, see above).
        var firstRequest = host.PostStageAsync("/api/public-uploads/stage", first, body.Length, host.Csrf, draft, "198.51.100.1");
        Task<HttpContext>? secondRequest = null;
        try
        {
            await host.WaitUntilReadingAsync(first, firstRequest);
            secondRequest = host.PostStageAsync("/api/public-uploads/stage", second, body.Length, host.Csrf, draft, "198.51.100.2");
            await host.WaitUntilReadingAsync(second, secondRequest);

            var third = new ThrowingStream();
            var thirdContext = await host.PostStageAsync("/api/public-uploads/stage", third, body.Length, host.Csrf, draft, "198.51.100.3").WaitAsync(Host.Timeout);
            Assert.Equal(StatusCodes.Status429TooManyRequests, thirdContext.Response.StatusCode);
            Assert.False(third.ReadAttempted);
        }
        finally
        {
            first.Release();
            second.Release();
        }

        Assert.Equal(StatusCodes.Status200OK, (await firstRequest.WaitAsync(Host.Timeout)).Response.StatusCode);
        Assert.Equal(StatusCodes.Status200OK, (await secondRequest!.WaitAsync(Host.Timeout)).Response.StatusCode);
        await host.WaitForNoUploadsInFlightAsync(UploadConcurrency.DraftKey(draft));
    }

    [Fact]
    public async Task Stage_accepts_a_file_larger_than_the_app_wide_form_limit()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = Host.MultipartBody(new string('x', 3 * 1024 * 1024));

        var context = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), body.Length, host.Csrf);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
    }

    [Fact]
    public async Task Stage_reserves_only_what_the_draft_still_accepts()
    {
        const long maxTotal = 100_000;
        await using var host = await Host.StartAsync(scratchMaxBytes: 0, maxTotalUploadBytes: maxTotal);
        var body = Host.MultipartBody("hello");
        var gate = new GateStream(body);

        var request = host.PostStageAsync("/api/public-uploads/stage", gate, contentLength: null, host.Csrf);
        try
        {
            await host.WaitUntilReadingAsync(gate, request);
            // A chunked body reserves the draft's remaining allowance plus overhead, not the 10 MiB endpoint limit.
            Assert.Equal(maxTotal + UploadStagingEndpoints.MultipartOverheadBytes, host.Scratch.Reserved.ScratchBytes);
        }
        finally
        {
            gate.Release();
        }

        Assert.Equal(StatusCodes.Status200OK, (await request.WaitAsync(Host.Timeout)).Response.StatusCode);
    }

    [Fact]
    public async Task Stage_declaring_more_than_the_draft_accepts_is_413_before_the_body_is_read()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0, maxTotalUploadBytes: 100_000);
        var body = new ThrowingStream();

        var context = await host.PostStageAsync("/api/public-uploads/stage", body, contentLength: 5L * 1024 * 1024, host.Csrf);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Equal(UploadStagingEndpoints.TooLargeMessage, await host.ErrorAsync(context));
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Public_stage_over_the_link_budget_is_413_and_opens_no_draft()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0, configure: o => o.PublicUploads.MaxOpenDraftBytesPerToken = 10);
        var held = await host.WithManagerAsync(async m =>
        {
            var draft = await m.EnsurePublicUploadDraftAsync(host.OwnerId, null, UploadCode, "203.0.113.9", CancellationToken.None);
            await m.StageUploadAsync(host.OwnerId, draft, "a.bin", 10, new MemoryStream(new byte[10]), CancellationToken.None);
            return draft;
        });
        var newDraft = Guid.NewGuid().ToString("N");
        var body = new ThrowingStream();

        var context = await host.PostStageAsync("/api/public-uploads/stage", body, 100, host.Csrf, newDraft);

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
        var drafts = Path.Combine(host.StorageRoot, "uploads", "drafts");
        Assert.False(Directory.Exists(Path.Combine(drafts, newDraft)));
        Assert.Equal([held], Directory.EnumerateDirectories(drafts).Select(Path.GetFileName));
    }

    [Fact]
    public async Task Public_stage_declaring_more_than_the_global_cap_admits_is_507_not_413()
    {
        // Budget 10,000,000 (capacity, no floor); 0.1% of it = 10,000 bytes for all open anonymous drafts.
        await using var host = await Host.StartAsync(
            scratchMaxBytes: 0, configure: o => o.PublicUploads.MaxOpenDraftScratchFraction = 0.001, totalCapacity: _ => 10_000_000);
        var body = new ThrowingStream();

        var context = await host.PostStageAsync("/api/public-uploads/stage", body, 2L * 1024 * 1024, host.Csrf);

        Assert.Equal(StatusCodes.Status507InsufficientStorage, context.Response.StatusCode);
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Public_stage_refuses_a_signed_in_draft_like_someone_elses()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var signedInDraft = await host.WithManagerAsync(m => m.EnsureDraftShareAsync(host.OwnerId, null, CancellationToken.None));
        var body = new ThrowingStream();

        var context = await host.PostStageAsync("/api/public-uploads/stage", body, 100, host.Csrf, signedInDraft);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.Equal("Draft share does not belong to the current user.", await host.ErrorAsync(context));
        Assert.False(body.ReadAttempted);
    }

    [Fact]
    public async Task Signed_in_paths_refuse_a_public_upload_draft_like_someone_elses()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var body = Host.MultipartBody("hello");
        var publicDraft = Guid.NewGuid().ToString("N");
        var staged = await host.PostStageAsync("/api/public-uploads/stage", new MemoryStream(body), body.Length, host.Csrf, publicDraft);
        Assert.Equal(StatusCodes.Status200OK, staged.Response.StatusCode);
        var uploadId = JsonDocument.Parse(await host.BodyAsync(staged)).RootElement.GetProperty("uploadId").GetString()!;

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            host.WithManagerAsync(m => m.EnsureDraftShareAsync(host.OwnerId, publicDraft, CancellationToken.None)));
        Assert.Equal("Draft share does not belong to the current user.", refused.Message);
        Assert.False(await host.WithManagerAsync(m => m.DeleteStagedUploadAsync(host.OwnerId, publicDraft, uploadId, CancellationToken.None)));
        Assert.Single(await host.WithManagerAsync(m => m.ListStagedUploadsForDraftAsync(host.OwnerId, publicDraft, CancellationToken.None)));

        // The per-share design and the signed-in read paths treat it the same way.
        var template = new ShareTemplateData("t", "h", "d", null, null, "center");
        var designRefused = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            host.WithManagerAsync(async m => { await m.SaveDraftTemplateAsync(host.OwnerId, publicDraft, "per_upload", template, null, CancellationToken.None); return true; }));
        Assert.Equal("Draft share does not belong to the current user.", designRefused.Message);
        Assert.False(await host.WithManagerAsync(m => m.IsOwnSignedInDraftAsync(host.OwnerId, publicDraft, CancellationToken.None)));
        var signedInDraft = await host.WithManagerAsync(m => m.EnsureDraftShareAsync(host.OwnerId, null, CancellationToken.None));
        Assert.True(await host.WithManagerAsync(m => m.IsOwnSignedInDraftAsync(host.OwnerId, signedInDraft, CancellationToken.None)));
    }

    [Fact]
    public async Task Template_background_over_the_pixel_budget_or_not_an_image_is_refused_before_staging()
    {
        await using var host = await Host.StartAsync(scratchMaxBytes: 0);
        var csrf = await host.FetchCsrfAsync(host.OwnerId);
        var draft = await host.WithManagerAsync(m => m.EnsureDraftShareAsync(host.OwnerId, null, CancellationToken.None));

        // A tiny PNG whose header declares 6300x6300 (39.7 million pixels, above the 16 million PNG budget).
        foreach (var refused in new[] { PngCrafting.HeaderWithIdat(6300, 6300), "not an image"u8.ToArray() })
        {
            var body = Host.MultipartBody(refused, "bg.png", "image/png");
            var context = await host.PostStageAsync("/api/uploads/stage-template-background", new MemoryStream(body), body.Length, csrf, draft, user: host.OwnerId);

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
            Assert.Equal(OgImageGenerator.BackgroundRefusalMessage, await host.ErrorAsync(context));
        }

        var stagedRoot = Path.Combine(host.StorageRoot, "uploads", "staged-template-backgrounds");
        Assert.True(!Directory.Exists(stagedRoot) || !Directory.EnumerateFileSystemEntries(stagedRoot).Any());

        var accepted = Host.MultipartBody(ImageCrafting.Solid(1920, 1080, new SKColor(30, 60, 90)), "bg.png", "image/png");
        var ok = await host.PostStageAsync("/api/uploads/stage-template-background", new MemoryStream(accepted), accepted.Length, csrf, draft, user: host.OwnerId);

        Assert.Equal(StatusCodes.Status200OK, ok.Response.StatusCode);

        // A 24 megapixel JPEG (an ordinary camera photo) is within the JPEG budget.
        var photo = Host.MultipartBody(ImageCrafting.JpegDeclaringSize(6000, 4000), "photo.jpg", "image/jpeg");
        var photoOk = await host.PostStageAsync("/api/uploads/stage-template-background", new MemoryStream(photo), photo.Length, csrf, draft, user: host.OwnerId);

        Assert.Equal(StatusCodes.Status200OK, photoOk.Response.StatusCode);
    }

    private sealed record CsrfTokens(string CookieHeader, string? HeaderToken);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;

        public string StorageRoot { get; }
        public ScratchSpaceMonitor Scratch { get; }
        public Guid OwnerId { get; private set; }
        public CsrfTokens Csrf { get; private set; } = new(string.Empty, null);

        private Host(WebApplication app, SqliteConnection connection, string storageRoot, ScratchSpaceMonitor scratch)
        {
            _app = app;
            _connection = connection;
            StorageRoot = storageRoot;
            Scratch = scratch;
        }

        public static async Task<Host> StartAsync(
            long scratchMaxBytes, long? maxTotalUploadBytes = null, Action<AgoraOptions>? configure = null, Func<string, long>? totalCapacity = null)
        {
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-stage-endpoint-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = new AgoraOptions { StorageRoot = storageRoot, Scratch = { MaxBytes = scratchMaxBytes, MinFreeBytes = 0 } };
            configure?.Invoke(options);
            var scratch = new ScratchSpaceMonitor(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System, totalCapacityBytes: totalCapacity);
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o =>
            {
                o.StorageRoot = storageRoot;
                o.Scratch = options.Scratch;
                o.MaxTotalUploadBytes = maxTotalUploadBytes ?? o.MaxTotalUploadBytes;
                configure?.Invoke(o);
            });
            // As in Program.cs: small app-wide form limits; the stage endpoints pass their own per call.
            builder.Services.Configure<Microsoft.AspNetCore.Http.Features.FormOptions>(FormLimits.Configure);
            builder.Services.AddSingleton<UploadConcurrency>();
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

            builder.Services.AddAuthorization();

            var app = builder.Build();
            // Test sign-in: the X-Test-User header becomes the session principal (the seeded owner's email).
            app.Use(async (context, next) =>
            {
                if (Guid.TryParse(context.Request.Headers["X-Test-User"].ToString(), out var userId))
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim(ClaimTypes.NameIdentifier, userId.ToString()), new Claim(ClaimTypes.Email, Owner)],
                        authenticationType: "Test"));
                }

                await next();
            });
            app.UseRouting();
            app.UseAgoraCsrf(isE2E: false, CookieSecurePolicy.None, NullLogger.Instance);
            app.UseRateLimiter();
            app.UseAuthorization();
            app.MapGet("/", () => Results.Ok());
            app.MapUploadStagingEndpoints(stageRequestBodyLimit: 10 * 1024 * 1024);
            await app.StartAsync();

            var ownerId = Guid.NewGuid();
            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(new UserAccount
                {
                    Id = ownerId,
                    Email = Owner,
                    EmailConfirmed = true,
                    PasswordHash = "x",
                    UploadToken = UploadCode,
                    IsEnabled = true,
                    CreatedAtUtc = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }

            var host = new Host(app, connection, storageRoot, scratch) { OwnerId = ownerId };
            host.Csrf = await host.FetchCsrfAsync(user: null);
            return host;
        }

        /// <summary>Antiforgery tokens are bound to the signed-in user, so a signed-in request needs its own.</summary>
        public async Task<CsrfTokens> FetchCsrfAsync(Guid? user)
        {
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = "/";
                if (user is { } userId)
                {
                    ctx.Request.Headers["X-Test-User"] = userId.ToString();
                }
            });

            var cookies = context.Response.Headers.SetCookie
                .Select(value => (value ?? string.Empty).Split(';')[0])
                .ToList();
            var requestToken = cookies
                .Select(pair => pair.Split('=', 2))
                .Single(parts => parts[0] == CsrfValidation.RequestTokenCookieName)[1];
            return new CsrfTokens(string.Join("; ", cookies), Uri.UnescapeDataString(requestToken));
        }

        public static byte[] MultipartBody(string content) => MultipartBody(Encoding.ASCII.GetBytes(content), "a.txt", "text/plain");

        public static byte[] MultipartBody(byte[] content, string fileName, string contentType) =>
        [
            .. Encoding.ASCII.GetBytes(
                $"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fileName}\"\r\nContent-Type: {contentType}\r\n\r\n"),
            .. content,
            .. "\r\n--b--\r\n"u8
        ];

        public async Task<T> WithManagerAsync<T>(Func<ShareManager, Task<T>> action)
        {
            using var scope = _app.Services.CreateScope();
            return await action(scope.ServiceProvider.GetRequiredService<ShareManager>());
        }

        public async Task<string> BodyAsync(HttpContext context)
        {
            if (context.Response.Body.CanSeek)
            {
                context.Response.Body.Position = 0;
            }

            return await new StreamReader(context.Response.Body).ReadToEndAsync();
        }

        public async Task<string?> ErrorAsync(HttpContext context) =>
            JsonDocument.Parse(await BodyAsync(context)).RootElement.GetProperty("error").GetString();

        /// <summary>Bound for every await on a request, so a broken test fails instead of hanging the run.</summary>
        public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Waits until the request is blocked reading its gated body; fails (with the response it gave instead) when
        /// the request ended without reading, or after <see cref="Timeout"/>.
        /// </summary>
        public async Task WaitUntilReadingAsync(GateStream gate, Task<HttpContext> request)
        {
            var finished = await Task.WhenAny(gate.Started.Task, request, Task.Delay(Timeout));
            if (finished == gate.Started.Task)
            {
                return;
            }

            if (finished == request)
            {
                var context = await request;
                Assert.Fail($"The request ended before reading its body: {context.Response.StatusCode} {await BodyAsync(context)}");
            }

            Assert.Fail("The request neither read its body nor finished in time.");
        }

        public async Task WaitForNoUploadsInFlightAsync(string key)
        {
            var concurrency = _app.Services.GetRequiredService<UploadConcurrency>();
            for (var i = 0; i < 100 && concurrency.InFlight(key) > 0; i++)
            {
                await Task.Delay(20);
            }

            Assert.Equal(0, concurrency.InFlight(key));
        }

        public Task<HttpContext> PostStageAsync(string path, Stream body, long? contentLength, CsrfTokens csrf, string? draftShareId = null, string remoteIp = "203.0.113.1", Guid? user = null)
        {
            return _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Post;
                ctx.Request.Path = path;
                ctx.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
                ctx.Request.QueryString = new QueryString($"?uploadToken={UploadCode}&draftShareId={draftShareId ?? Guid.NewGuid().ToString("N")}");
                ctx.Request.ContentType = "multipart/form-data; boundary=b";
                ctx.Request.ContentLength = contentLength;
                ctx.Request.Body = body;
                ctx.Request.Headers.Cookie = csrf.CookieHeader;
                if (user is { } userId)
                {
                    ctx.Request.Headers["X-Test-User"] = userId.ToString();
                }

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
