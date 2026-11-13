using System.Net;
using System.Security.Claims;
using System.Text;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Endpoints;
using Agora.Web.Pages;
using Agora.Web.Services;
using Agora.Web.Startup;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
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
/// The public share page and its routes: a password-protected share shows nothing of itself until unlocked, original
/// bytes are never cacheable, only the owner's own downloads go uncounted, a freshly failed preview is not re-run on
/// demand, the page shares the per-share download rate limit, and a link-preview image whose background could not be
/// decoded within the shared decode slots is served but not cached.
/// </summary>
[Collection(RasterDecodeSlotsCollection.Name)]
public sealed class PublicSharePageTests
{
    private const string Password = "correct-horse";
    private const string SecretName = "quarterly-secret.zip";
    private const string SecretH1 = "Board pack for Q3";
    private const string SecretDescription = "Strictly internal numbers";
    private const string BackgroundKey = "backgrounds/2026/11/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.png";
    private static readonly Guid OwnerId = Guid.NewGuid();
    private static readonly Guid OtherUserId = Guid.NewGuid();

    [Fact]
    public async Task A_password_share_shows_a_generic_card_until_the_password_was_entered()
    {
        await using var host = await Host.StartAsync();
        var share = await host.AddShareAsync("locked01", password: Password);
        await host.AddShareAsync("locked02", password: "another-password");

        var locked = await host.SendAsync(HttpMethods.Get, "/s/locked01");
        Assert.Equal(StatusCodes.Status200OK, locked.Status);
        Assert.Contains("Password-protected share", locked.Body);
        Assert.Contains("<title>Password-protected share - Agora</title>", locked.Body);
        Assert.Contains("action=\"/s/locked01/unlock\"", locked.Body);
        foreach (var secret in new[] { SecretName, SecretH1, SecretDescription, "/background", "#123456" })
        {
            Assert.DoesNotContain(secret, locked.Body);
        }

        Assert.Equal(StatusCodes.Status404NotFound, (await host.SendAsync(HttpMethods.Get, "/s/locked01/background")).Status);

        var wrong = await host.PostFormAsync("/s/locked01/unlock", $"downloadPassword={Uri.EscapeDataString("nope")}");
        Assert.Equal(StatusCodes.Status302Found, wrong.Status);
        Assert.EndsWith("downloadError=invalid_password", wrong.Headers.Location.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(wrong.Headers.SetCookie, c => (c ?? string.Empty).StartsWith(ShareUnlockGate.CookieName, StringComparison.Ordinal));

        var right = await host.PostFormAsync("/s/locked01/unlock", $"downloadPassword={Uri.EscapeDataString(Password)}");
        Assert.Equal(StatusCodes.Status302Found, right.Status);
        Assert.Equal("/s/locked01", right.Headers.Location.ToString());
        var setCookie = Assert.Single(right.Headers.SetCookie, c => (c ?? string.Empty).StartsWith(ShareUnlockGate.CookieName, StringComparison.Ordinal))!;
        Assert.Contains("path=/s/locked01", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", setCookie, StringComparison.OrdinalIgnoreCase);
        var unlockCookie = setCookie.Split(';')[0];

        var unlocked = await host.SendAsync(HttpMethods.Get, "/s/locked01", unlockCookie);
        Assert.Contains(SecretName, unlocked.Body);
        Assert.Contains(SecretH1, unlocked.Body);
        Assert.Contains("/s/locked01/background", unlocked.Body);
        Assert.Contains("id=\"download-password\"", unlocked.Body);

        var background = await host.SendAsync(HttpMethods.Get, "/s/locked01/background", unlockCookie);
        Assert.Equal(StatusCodes.Status200OK, background.Status);
        Assert.Equal("private, no-store", background.Headers.CacheControl.ToString());

        // The cookie names the share it unlocks; another share's page stays locked with it.
        var other = await host.SendAsync(HttpMethods.Get, "/s/locked02", unlockCookie);
        Assert.Contains("Password-protected share", other.Body);
        Assert.DoesNotContain(SecretName, other.Body);
        Assert.NotEqual(Guid.Empty, share.Id);
    }

    [Fact]
    public async Task Tampered_or_expired_unlock_cookies_keep_the_share_locked()
    {
        await using var host = await Host.StartAsync();
        var share = await host.AddShareAsync("locked03", password: Password);

        var valid = host.UnlockCookieValue(share.Id, DateTimeOffset.UtcNow.AddHours(1));
        Assert.Contains(SecretName, (await host.SendAsync(HttpMethods.Get, "/s/locked03", $"{ShareUnlockGate.CookieName}={valid}")).Body);

        var tampered = valid[..^4] + (valid[^4..] == "AAAA" ? "BBBB" : "AAAA");
        var expired = host.UnlockCookieValue(share.Id, DateTimeOffset.UtcNow.AddMinutes(-1));
        foreach (var cookie in new[] { tampered, expired, "garbage", share.Id.ToString("N") })
        {
            var page = await host.SendAsync(HttpMethods.Get, "/s/locked03", $"{ShareUnlockGate.CookieName}={cookie}");
            Assert.Contains("Password-protected share", page.Body);
            Assert.DoesNotContain(SecretName, page.Body);
            Assert.Equal(StatusCodes.Status404NotFound, (await host.SendAsync(HttpMethods.Get, "/s/locked03/background", $"{ShareUnlockGate.CookieName}={cookie}")).Status);
        }
    }

    [Fact]
    public async Task An_expired_password_share_renders_the_generic_expired_card()
    {
        await using var host = await Host.StartAsync();
        await host.AddShareAsync("expired1", password: Password, expiresAtUtc: DateTime.UtcNow.AddMinutes(-1));

        var page = await host.SendAsync(HttpMethods.Get, "/s/expired1");
        Assert.Equal(StatusCodes.Status410Gone, page.Status);
        Assert.Contains("This link has expired", page.Body);
        Assert.DoesNotContain(SecretName, page.Body);
        Assert.DoesNotContain(SecretH1, page.Body);
    }

    [Fact]
    public async Task A_busy_redirect_shows_a_friendly_note_on_the_share_page()
    {
        await using var host = await Host.StartAsync();
        await host.AddShareAsync("busy0001", password: Password);

        var page = await host.SendAsync(HttpMethods.Get, "/s/busy0001?downloadError=busy");
        Assert.Equal(StatusCodes.Status200OK, page.Status);
        Assert.Contains("The server is busy right now", page.Body);
    }

    [Fact]
    public async Task External_background_values_render_no_background_image()
    {
        await using var host = await Host.StartAsync();
        await host.AddShareAsync("external", background: "https://evil.example/x.png);color:red");

        var page = await host.SendAsync(HttpMethods.Get, "/s/external");
        Assert.Equal(StatusCodes.Status200OK, page.Status);
        Assert.DoesNotContain("evil.example", page.Body);
        Assert.DoesNotContain("background-image", page.Body);
    }

    [Fact]
    public async Task Only_the_owner_skips_download_recording_and_originals_are_not_cacheable()
    {
        await using var host = await Host.StartAsync();
        var share = await host.AddShareAsync("counted1", archive: true);

        var owner = await host.PostFormAsync("/s/counted1/download", string.Empty, user: OwnerId);
        Assert.Equal(StatusCodes.Status200OK, owner.Status);
        Assert.Equal("private, no-store", owner.Headers.CacheControl.ToString());
        Assert.Equal(0, await host.DownloadCountAsync(share.Id));

        var otherUser = await host.PostFormAsync("/s/counted1/download", string.Empty, user: OtherUserId);
        Assert.Equal(StatusCodes.Status200OK, otherUser.Status);
        Assert.Equal(1, await host.DownloadCountAsync(share.Id));

        var anonymous = await host.PostFormAsync("/s/counted1/download", string.Empty);
        Assert.Equal(StatusCodes.Status200OK, anonymous.Status);
        Assert.Equal(2, await host.DownloadCountAsync(share.Id));
    }

    [Fact]
    public async Task Preview_share_files_are_not_cacheable_and_a_fresh_failure_is_not_retried()
    {
        await using var host = await Host.StartAsync();
        var share = await host.AddShareAsync("preview1", accessMode: "preview_and_download", withFile: true);
        var fileId = share.Files.Single().Id;

        var file = await host.SendAsync(HttpMethods.Get, $"/s/preview1/files/{fileId}");
        Assert.Equal(StatusCodes.Status200OK, file.Status);
        Assert.Equal("private, no-store", file.Headers.CacheControl.ToString());

        var failedPath = SharePreviewPaths.FailedPath(host.StorageRoot, share.Id, fileId);
        Directory.CreateDirectory(Path.GetDirectoryName(failedPath)!);
        await File.WriteAllTextAsync(failedPath, DateTime.UtcNow.ToString("O"));
        File.SetLastWriteTimeUtc(failedPath, DateTime.UtcNow.AddMinutes(-10));
        var jobsBefore = host.Jobs.Count;

        var refused = await host.SendAsync(HttpMethods.Get, $"/s/preview1/files/{fileId}/preview/retry");
        Assert.Equal(StatusCodes.Status200OK, refused.Status);
        Assert.Contains("generation_failed", refused.Body);
        var retryAfter = int.Parse(refused.Headers.RetryAfter.ToString());
        Assert.InRange(retryAfter, 19 * 60, 20 * 60);
        Assert.Equal(jobsBefore, host.Jobs.Count);

        File.SetLastWriteTimeUtc(failedPath, DateTime.UtcNow.AddMinutes(-31));
        var accepted = await host.SendAsync(HttpMethods.Get, $"/s/preview1/files/{fileId}/preview/retry");
        Assert.Equal(StatusCodes.Status202Accepted, accepted.Status);
        Assert.Equal(jobsBefore + 1, host.Jobs.Count);
    }

    [Fact]
    public async Task The_share_page_counts_against_the_download_rate_limit()
    {
        await using var host = await Host.StartAsync();
        await host.AddShareAsync("limited1");

        for (var i = 0; i < 20; i++)
        {
            Assert.Equal(StatusCodes.Status200OK, (await host.SendAsync(HttpMethods.Get, "/s/limited1")).Status);
        }

        Assert.Equal(StatusCodes.Status429TooManyRequests, (await host.SendAsync(HttpMethods.Get, "/s/limited1")).Status);
        Assert.Equal(StatusCodes.Status429TooManyRequests, (await host.SendAsync(HttpMethods.Get, "/s/limited1/background")).Status);
    }

    [Fact]
    public async Task The_new_share_page_never_takes_its_share_token_from_the_query()
    {
        await using var host = await Host.StartAsync();

        var page = await host.SendAsync(HttpMethods.Get, "/shares/new?shareToken=attacker1&suggestedShareToken=attacker2&msg=Share%20design%20saved", user: OwnerId);

        Assert.Equal(StatusCodes.Status200OK, page.Status);
        var token = System.Text.RegularExpressions.Regex.Match(page.Body, "name=\"shareToken\" value=\"([^\"]*)\"").Groups[1].Value;
        Assert.True(ShareTokens.IsValid(token));
        Assert.NotEqual("attacker1", token);
        Assert.DoesNotContain("attacker1", page.Body);
        Assert.DoesNotContain("attacker2", page.Body);
        Assert.DoesNotContain("data-suggested-share-token", page.Body);
        // The designer redirects still reach the page with their message.
        Assert.Contains("Share design saved", page.Body);
    }

    [Fact]
    public async Task A_disabled_owners_shares_read_as_expired_until_the_account_is_enabled_again()
    {
        await using var host = await Host.StartAsync();
        var share = await host.AddShareAsync("ownerofs", archive: true, accessMode: "preview_and_download", withFile: true);
        var fileId = share.Files.Single().Id;
        await host.AddShareAsync("ownerdl1", accessMode: "direct_link", withFile: true);
        var orphan = await host.AddShareAsync("orphan01");
        await host.ClearOwnerAsync(orphan.Id);

        await host.SetOwnerEnabledAsync(false);

        var page = await host.SendAsync(HttpMethods.Get, "/s/ownerofs");
        Assert.Equal(StatusCodes.Status410Gone, page.Status);
        Assert.Contains("This link has expired", page.Body);
        Assert.DoesNotContain(SecretH1, page.Body);
        var directLink = await host.SendAsync(HttpMethods.Get, "/s/ownerdl1");
        Assert.Equal(StatusCodes.Status410Gone, directLink.Status);
        Assert.Contains("This link has expired", directLink.Body);
        Assert.Equal(StatusCodes.Status410Gone, (await host.PostFormAsync("/s/ownerofs/download", string.Empty)).Status);
        foreach (var path in new[] { "/s/ownerofs/background", "/s/ownerofs/files", $"/s/ownerofs/files/{fileId}", $"/s/ownerofs/files/{fileId}/preview-status" })
        {
            Assert.Equal(StatusCodes.Status410Gone, (await host.SendAsync(HttpMethods.Get, path)).Status);
        }

        Assert.Equal(0, await host.DownloadCountAsync(share.Id));
        // A legacy row without an owner is not affected.
        Assert.Equal(StatusCodes.Status200OK, (await host.SendAsync(HttpMethods.Get, "/s/orphan01")).Status);

        await host.SetOwnerEnabledAsync(true);

        Assert.Equal(StatusCodes.Status200OK, (await host.SendAsync(HttpMethods.Get, "/s/ownerofs")).Status);
        var served = await host.SendAsync(HttpMethods.Get, "/s/ownerdl1");
        Assert.Equal(StatusCodes.Status200OK, served.Status);
        Assert.Equal("hello", served.Body);
        Assert.Equal(StatusCodes.Status200OK, (await host.PostFormAsync("/s/ownerofs/download", string.Empty)).Status);
        Assert.Equal(StatusCodes.Status200OK, (await host.SendAsync(HttpMethods.Get, $"/s/ownerofs/files/{fileId}")).Status);
    }

    [Fact]
    public async Task Og_image_falls_back_uncached_while_the_decode_slots_are_busy_and_is_cached_once_rendered()
    {
        await using var host = await Host.StartAsync();
        const string backgroundKey = "backgrounds/2026/11/cccccccccccccccccccccccccccccccc.png";
        await host.ObjectStore.PutBytesAsync(backgroundKey, ImageCrafting.Solid(64, 48, new SkiaSharp.SKColor(30, 60, 90)), "image/png", CancellationToken.None);
        var share = await host.AddShareAsync("ogslots1", background: $"internal:{backgroundKey}");
        var cacheKey = SharePreviewPaths.OgImageKey(share.Id);
        var slots = SharePreviewImageGenerator.RasterDecodeSlots;

        await slots.WaitAsync();
        await slots.WaitAsync();
        Response fallback;
        try
        {
            fallback = await host.SendAsync(HttpMethods.Get, "/s/ogslots1/og-image");
        }
        finally
        {
            slots.Release(2);
        }

        Assert.Equal(StatusCodes.Status200OK, fallback.Status);
        Assert.Equal("private, no-store", fallback.Headers.CacheControl.ToString());
        Assert.Null(await host.ObjectStore.OpenReadAsync(cacheKey, CancellationToken.None));

        var rendered = await host.SendAsync(HttpMethods.Get, "/s/ogslots1/og-image");

        Assert.Equal(StatusCodes.Status200OK, rendered.Status);
        Assert.Equal("public, max-age=3600", rendered.Headers.CacheControl.ToString());
        var cached = await host.ObjectStore.OpenReadAsync(cacheKey, CancellationToken.None);
        Assert.NotNull(cached);
        await cached.Content.DisposeAsync();
    }

    private sealed record Response(int Status, string Body, IHeaderDictionary Headers);

    private sealed class Host : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly SqliteConnection _connection;
        private readonly IObjectStore _objectStore;
        private readonly Dictionary<Guid, (string Cookies, string Token)> _csrf = [];

        private Host(WebApplication app, SqliteConnection connection, IObjectStore objectStore, string storageRoot, CountingJobClient jobs)
        {
            _app = app;
            _connection = connection;
            _objectStore = objectStore;
            StorageRoot = storageRoot;
            Jobs = jobs;
        }

        public string StorageRoot { get; }
        public CountingJobClient Jobs { get; }
        public IObjectStore ObjectStore => _objectStore;

        public static async Task<Host> StartAsync()
        {
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-share-page-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var objectStore = new FileSystemObjectStore(storageRoot);
            var jobs = new CountingJobClient();

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Services.Configure<AgoraOptions>(o => o.StorageRoot = storageRoot);
            builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
            builder.Services.AddSingleton<IObjectStore>(objectStore);
            builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
            builder.Services.AddSingleton<IBackgroundJobClient>(jobs);
            builder.Services.AddSingleton<KeyedAsyncLock>();
            builder.Services.AddSingleton(new Agora.Infrastructure.Auth.PasswordHashingGate());
            builder.Services.AddSingleton(new ScratchSpaceMonitor(new AgoraOptions { StorageRoot = storageRoot }, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
            builder.Services.AddScoped<ShareManager>();
            builder.Services.AddScoped<Agora.Infrastructure.Auth.AuthService>();
            builder.Services.AddSingleton<IEmailSender, NoopEmailSender>();
            builder.Services.AddAuthorization();
            builder.Services.AddScoped<IShareExperienceRenderer, ArchiveShareExperienceRenderer>();
            builder.Services.AddScoped<IShareExperienceRenderer, GalleryShareExperienceRenderer>();
            builder.Services.AddScoped<ShareExperienceRendererResolver>();
            builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: false));
            // A one-second budget so the og-image test that holds the decode slots falls back quickly.
            builder.Services.AddSingleton(_ => new OgImageGenerator(Path.Combine(AppContext.BaseDirectory, "Fonts"), decodeTimeoutSeconds: 1));
            builder.Services.AddSingleton<SharePreviewImageGenerator>();
            builder.Services.AddScoped<SharePreviewJobService>();
            builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
            builder.Services.AddAntiforgery(o =>
            {
                o.Cookie.Name = "agora.csrf";
                o.FormFieldName = "__RequestVerificationToken";
                o.HeaderName = CsrfValidation.HeaderName;
            });
            builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions(), isE2E: true));
            var app = builder.Build();
            // Test sign-in: the X-Test-User header becomes the session principal.
            app.Use(async (context, next) =>
            {
                if (Guid.TryParse(context.Request.Headers["X-Test-User"].ToString(), out var userId))
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim(ClaimTypes.NameIdentifier, userId.ToString()), new Claim(ClaimTypes.Email, $"{userId:N}@example.com")],
                        authenticationType: "Test"));
                }

                await next();
            });
            app.UseRouting();
            app.UseAuthorization();
            app.UseAgoraCsrf(isE2E: false, CookieSecurePolicy.None, NullLogger.Instance);
            app.UseRateLimiter();
            app.MapGet("/", () => Results.Ok());
            app.MapRazorPages();
            app.MapPublicShareEndpoints();
            await app.StartAsync();

            using (var scope = app.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(TestUsers.Seed(OwnerId, "owner@example.com"));
                await db.SaveChangesAsync();
            }

            await objectStore.PutBytesAsync(BackgroundKey, "png"u8.ToArray(), "image/png", CancellationToken.None);
            return new Host(app, connection, objectStore, storageRoot, jobs);
        }

        public async Task<Share> AddShareAsync(
            string token,
            string? password = null,
            DateTime? expiresAtUtc = null,
            string? background = null,
            bool archive = false,
            string accessMode = "download_only",
            bool withFile = false)
        {
            var zipKey = $"zips/2026/11/{token}.zip";
            if (archive)
            {
                await _objectStore.PutBytesAsync(zipKey, "zip-bytes"u8.ToArray(), "application/zip", CancellationToken.None);
            }

            var share = new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = OwnerId,
                UploaderEmail = "owner@example.com",
                ShareToken = token,
                ZipDisplayName = SecretName,
                ZipDiskPath = zipKey,
                ZipSizeBytes = 9,
                AccessMode = accessMode,
                PageH1 = SecretH1,
                PageTitle = SecretH1,
                PageDescription = SecretDescription,
                PageBackgroundColorHex = "#123456",
                BackgroundImageUrl = background ?? $"internal:{BackgroundKey}",
                DownloadPasswordHash = password is null ? null : PasswordHasher.Hash(password),
                ExpiresAtUtc = expiresAtUtc,
                CreatedAtUtc = DateTime.UtcNow
            };
            if (withFile)
            {
                var fileKey = $"shares/2026/11/{token}/notes.txt";
                await _objectStore.PutBytesAsync(fileKey, "hello"u8.ToArray(), "text/plain", CancellationToken.None);
                share.Files = [new ShareFile { Id = Guid.NewGuid(), OriginalFilename = "notes.txt", StoredRelativePath = fileKey, RenderType = "text", OriginalSizeBytes = 5, DetectedContentType = "text/plain" }];
            }

            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(share);
            await db.SaveChangesAsync();
            return share;
        }

        /// <summary>An unlock cookie value as the app would issue it, with a chosen expiry.</summary>
        public string UnlockCookieValue(Guid shareId, DateTimeOffset expiresAt) =>
            _app.Services.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>()
                .CreateProtector(ShareUnlockGate.Purpose)
                .ToTimeLimitedDataProtector()
                .Protect(shareId.ToString("N"), expiresAt);

        public async Task SetOwnerEnabledAsync(bool enabled)
        {
            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var owner = await db.Users.SingleAsync(x => x.Id == OwnerId);
            owner.IsEnabled = enabled;
            await db.SaveChangesAsync();
        }

        public async Task ClearOwnerAsync(Guid shareId)
        {
            using var scope = _app.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var share = await db.Shares.SingleAsync(x => x.Id == shareId);
            share.OwnerUserId = null;
            await db.SaveChangesAsync();
        }

        public async Task<int> DownloadCountAsync(Guid shareId)
        {
            using var scope = _app.Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().DownloadEvents.CountAsync(x => x.ShareId == shareId);
        }

        public async Task<Response> SendAsync(string method, string path, string? cookie = null, Guid? user = null)
        {
            var body = new MemoryStream();
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = method;
                var query = path.IndexOf('?');
                ctx.Request.Path = query < 0 ? path : path[..query];
                ctx.Request.QueryString = query < 0 ? QueryString.Empty : new QueryString(path[query..]);
                if (cookie is not null)
                {
                    ctx.Request.Headers.Cookie = cookie;
                }

                if (user is { } userId)
                {
                    ctx.Request.Headers["X-Test-User"] = userId.ToString();
                }

                ctx.Response.Body = body;
            });
            return new Response(context.Response.StatusCode, Encoding.UTF8.GetString(body.ToArray()), context.Response.Headers);
        }

        public async Task<Response> PostFormAsync(string path, string form, Guid? user = null)
        {
            // Antiforgery tokens are bound to the signed-in user, so each test user gets its own.
            var csrfKey = user ?? Guid.Empty;
            if (!_csrf.TryGetValue(csrfKey, out var csrfPair))
            {
                var csrf = await SendAsync(HttpMethods.Get, "/", user: user);
                var cookies = csrf.Headers.SetCookie.Select(value => (value ?? string.Empty).Split(';')[0]).ToList();
                var token = cookies
                    .Select(pair => pair.Split('=', 2))
                    .Where(parts => parts.Length == 2 && parts[0] == CsrfValidation.RequestTokenCookieName)
                    .Select(parts => Uri.UnescapeDataString(parts[1]))
                    .Single();
                csrfPair = (string.Join("; ", cookies), token);
                _csrf[csrfKey] = csrfPair;
            }

            var payload = Encoding.UTF8.GetBytes($"__RequestVerificationToken={Uri.EscapeDataString(csrfPair.Token)}{(form.Length == 0 ? string.Empty : "&" + form)}");
            var body = new MemoryStream();
            var context = await _app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Post;
                ctx.Request.Path = path;
                ctx.Request.Headers.Cookie = csrfPair.Cookies;
                if (user is { } userId)
                {
                    ctx.Request.Headers["X-Test-User"] = userId.ToString();
                }

                ctx.Request.ContentType = "application/x-www-form-urlencoded";
                ctx.Request.ContentLength = payload.Length;
                ctx.Request.Body = new MemoryStream(payload);
                ctx.Response.Body = body;
            });
            return new Response(context.Response.StatusCode, Encoding.UTF8.GetString(body.ToArray()), context.Response.Headers);
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

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<string> RenderDownloadNotificationHtmlAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.FromResult(string.Empty);

        public Task<string> RenderAuthEmailHtmlAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }

    private sealed class CountingJobClient : IBackgroundJobClient
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public string Create(Job job, IState state)
        {
            Interlocked.Increment(ref _count);
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
