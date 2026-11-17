using System.Net;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Pages;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// The public page for direct links: a live one is the file itself (counted as a download), an expired or deleted
/// one is the expired page with 410, while a deleted ordinary share stays a 404.
/// </summary>
public sealed class DirectLinkPublicPageTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();

    [Fact]
    public async Task Direct_link_states_on_the_public_page()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), "agora-direct-link-page-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storageRoot);
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var objectStore = new FileSystemObjectStore(storageRoot);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.Configure<AgoraOptions>(o => o.StorageRoot = storageRoot);
        builder.Services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
        builder.Services.AddSingleton<IObjectStore>(objectStore);
        builder.Services.AddSingleton<IShareContentStore, ShareContentStore>();
        builder.Services.AddSingleton<IBackgroundJobClient, NoopJobClient>();
        builder.Services.AddSingleton<KeyedAsyncLock>();
        builder.Services.AddSingleton(new ScratchSpaceMonitor(new AgoraOptions { StorageRoot = storageRoot }, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System));
        builder.Services.AddScoped<ShareManager>();
        builder.Services.AddScoped<IShareExperienceRenderer, ArchiveShareExperienceRenderer>();
        builder.Services.AddScoped<IShareExperienceRenderer, GalleryShareExperienceRenderer>();
        builder.Services.AddScoped<ShareExperienceRendererResolver>();
        builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: false));
        builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
        await using var app = builder.Build();
        app.MapRazorPages();
        await app.StartAsync();

        const string liveKey = "shares/2026/10/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/photo.png";
        await objectStore.PutBytesAsync(liveKey, "png-bytes"u8.ToArray(), "image/png", CancellationToken.None);
        const string htmlKey = "shares/2026/10/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/report.html";
        await objectStore.PutBytesAsync(htmlKey, "<script>alert(1)</script>"u8.ToArray(), "text/html", CancellationToken.None);
        const string pdfKey = "shares/2026/10/cccccccccccccccccccccccccccccccc/report.pdf";
        await objectStore.PutBytesAsync(pdfKey, "%PDF-1.4"u8.ToArray(), "application/pdf", CancellationToken.None);
        var now = DateTime.UtcNow;
        Guid liveId;
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            await db.Database.EnsureCreatedAsync();
            var liveShare = DirectLink("livelink", now.AddHours(1), deletedAtUtc: null, liveKey);
            liveId = liveShare.Id;
            db.Shares.AddRange(
                liveShare,
                DirectLink("expiredl", now.AddMinutes(-1), deletedAtUtc: null, null),
                DirectLink("deletedl", now.AddHours(1), deletedAtUtc: now.AddMinutes(-5), null),
                DirectLink("purgedlk", now.AddMinutes(-1), deletedAtUtc: now.AddMinutes(-5), null),
                Ordinary("deletedo", deletedAtUtc: now.AddMinutes(-5)),
                DirectLink("htmllink", now.AddHours(1), deletedAtUtc: null, htmlKey, "report.html"),
                DirectLink("pdflink1", now.AddHours(1), deletedAtUtc: null, pdfKey, "report.pdf"));
            await db.SaveChangesAsync();
        }

        var server = app.GetTestServer();
        async Task<(int Status, string ContentType, string Body, IHeaderDictionary Headers)> GetAsync(string token, string? method = null)
        {
            var body = new MemoryStream();
            var ctx = await server.SendAsync(c =>
            {
                c.Request.Method = method ?? HttpMethods.Get;
                c.Request.Path = $"/s/{token}";
                c.Response.Body = body;
            });
            return (ctx.Response.StatusCode, ctx.Response.ContentType ?? string.Empty, System.Text.Encoding.UTF8.GetString(body.ToArray()), ctx.Response.Headers);
        }

        var live = await GetAsync("livelink");
        Assert.Equal((int)HttpStatusCode.OK, live.Status);
        Assert.Equal("image/png", live.ContentType);
        Assert.Equal("png-bytes", live.Body);
        Assert.Equal("nosniff", live.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal(Agora.Web.Endpoints.ObjectResults.UserContentCsp, live.Headers["Content-Security-Policy"].ToString());
        Assert.False(live.Headers.ContainsKey("Content-Disposition"));
        Assert.Equal("private, no-store", live.Headers.CacheControl.ToString());

        // An HTML direct link is always a download: never served as HTML, and sandboxed.
        var html = await GetAsync("htmllink");
        Assert.Equal((int)HttpStatusCode.OK, html.Status);
        Assert.Equal("application/octet-stream", html.ContentType);
        Assert.StartsWith("attachment", html.Headers.ContentDisposition.ToString());
        Assert.Contains("report.html", html.Headers.ContentDisposition.ToString());
        Assert.Equal(Agora.Web.Endpoints.ObjectResults.UserContentCsp, html.Headers["Content-Security-Policy"].ToString());
        Assert.Equal("nosniff", html.Headers["X-Content-Type-Options"].ToString());

        // A PDF direct link opens inline in the browser's viewer.
        var pdf = await GetAsync("pdflink1");
        Assert.Equal((int)HttpStatusCode.OK, pdf.Status);
        Assert.Equal("application/pdf", pdf.ContentType);
        Assert.False(pdf.Headers.ContainsKey("Content-Disposition"));

        // HEAD answers with the headers but is not a download.
        var head = await GetAsync("livelink", HttpMethods.Head);
        Assert.Equal((int)HttpStatusCode.OK, head.Status);
        Assert.Equal("image/png", head.ContentType);
        Assert.Equal(string.Empty, head.Body);

        foreach (var token in new[] { "expiredl", "deletedl", "purgedlk" })
        {
            var gone = await GetAsync(token);
            Assert.Equal((int)HttpStatusCode.Gone, gone.Status);
            Assert.Contains("text/html", gone.ContentType);
            Assert.Contains("This link has expired.", gone.Body);
            // Nothing of the file survives on the expired page: no name, title or H1, in the body or the meta tags.
            Assert.DoesNotContain("photo.png", gone.Body);
        }

        Assert.Equal((int)HttpStatusCode.NotFound, (await GetAsync("deletedo")).Status);
        Assert.Equal((int)HttpStatusCode.NotFound, (await GetAsync("unknown1")).Status);

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            Assert.Equal(1, await db.DownloadEvents.CountAsync(x => x.ShareId == liveId));
        }
    }

    private static Share DirectLink(string token, DateTime expiresAtUtc, DateTime? deletedAtUtc, string? storedKey, string fileName = "photo.png") => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = OwnerId,
        UploaderEmail = "owner@example.com",
        ShareToken = token,
        ZipDisplayName = "photo.png",
        ZipDiskPath = string.Empty,
        ZipSizeBytes = 9,
        ShareExperienceType = "archive",
        AccessMode = "direct_link",
        NotifyMode = "none",
        PageTitle = "photo.png",
        PageH1 = "photo.png",
        PageDescription = string.Empty,
        ExpiresAtUtc = expiresAtUtc,
        DeletedAtUtc = deletedAtUtc,
        CreatedAtUtc = DateTime.UtcNow,
        Files = storedKey is null
            ? []
            : [new ShareFile { Id = Guid.NewGuid(), OriginalFilename = fileName, StoredRelativePath = storedKey, RenderType = "image", OriginalSizeBytes = 9, DetectedContentType = ContentTypePolicy.FromFileName(fileName) }]
    };

    private static Share Ordinary(string token, DateTime? deletedAtUtc) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = OwnerId,
        UploaderEmail = "owner@example.com",
        ShareToken = token,
        ZipDisplayName = "files.zip",
        ZipDiskPath = "zips/2026/10/archive.zip",
        ZipSizeBytes = 9,
        DeletedAtUtc = deletedAtUtc,
        CreatedAtUtc = DateTime.UtcNow
    };

    private sealed class NoopJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
