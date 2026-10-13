using System.Net;
using System.Text;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
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
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Agora.Application.Tests;

/// <summary>
/// A password-protected archive is not opened in the object store (not even a metadata probe) until the share's
/// password has verified.
/// </summary>
public sealed class PublicShareDownloadGateTests
{
    private const string Token = "gatetest1";
    private const string Password = "correct-horse";

    [Fact]
    public async Task Wrong_password_never_touches_the_object_store()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), "agora-download-gate-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storageRoot);
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var objectStore = new RecordingObjectStore(new FileSystemObjectStore(storageRoot));

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
        // Injected by the og-image and preview endpoints of the same group; registered so they bind as services.
        builder.Services.AddSingleton(_ => new OgImageGenerator(Path.Combine(AppContext.BaseDirectory, "Fonts")));
        builder.Services.AddSingleton<SharePreviewImageGenerator>();
        builder.Services.AddScoped<SharePreviewJobService>();
        builder.Services.AddAntiforgery(o =>
        {
            o.Cookie.Name = "agora.csrf";
            o.FormFieldName = "__RequestVerificationToken";
            o.HeaderName = CsrfValidation.HeaderName;
        });
        builder.Services.AddRateLimiter(o => RateLimitSetup.Configure(o, new AgoraRateLimitOptions(), isE2E: true));
        await using var app = builder.Build();
        app.UseAgoraCsrf(isE2E: false, CookieSecurePolicy.None, NullLogger.Instance);
        app.UseRateLimiter();
        app.MapGet("/", () => Results.Ok());
        app.MapPublicShareEndpoints();
        await app.StartAsync();

        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            await db.Database.EnsureCreatedAsync();
            db.Shares.Add(new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = Guid.NewGuid(),
                UploaderEmail = "owner@example.com",
                ShareToken = Token,
                ZipDisplayName = "files.zip",
                ZipDiskPath = "zips/2026/10/archive.agz",
                DownloadPasswordHash = PasswordHasher.Hash(Password),
                CreatedAtUtc = DateTime.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        var server = app.GetTestServer();
        var (cookieHeader, requestToken) = await FetchCsrfAsync(server);

        var wrong = await PostDownloadAsync(server, cookieHeader, requestToken, "not-the-password");
        Assert.Equal(StatusCodes.Status302Found, wrong.Response.StatusCode);
        Assert.EndsWith("downloadError=invalid_password", wrong.Response.Headers.Location.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, objectStore.OpenReads);
        Assert.Equal(0, objectStore.InfoProbes);

        var missing = await PostDownloadAsync(server, cookieHeader, requestToken, string.Empty);
        Assert.Equal(StatusCodes.Status302Found, missing.Response.StatusCode);
        Assert.Equal(0, objectStore.OpenReads);

        // The right password reaches the store (the object is absent here, so the share answers 410).
        var right = await PostDownloadAsync(server, cookieHeader, requestToken, Password);
        Assert.Equal(StatusCodes.Status410Gone, right.Response.StatusCode);
        Assert.Equal(1, objectStore.OpenReads);
    }

    private static async Task<(string CookieHeader, string RequestToken)> FetchCsrfAsync(TestServer server)
    {
        var context = await server.SendAsync(ctx =>
        {
            ctx.Request.Method = HttpMethods.Get;
            ctx.Request.Path = "/";
        });
        var cookies = context.Response.Headers.SetCookie.Select(value => (value ?? string.Empty).Split(';')[0]).ToList();
        var requestToken = cookies
            .Select(pair => pair.Split('=', 2))
            .Where(parts => parts.Length == 2 && parts[0] == "agora.csrf.request")
            .Select(parts => Uri.UnescapeDataString(parts[1]))
            .Single();
        return (string.Join("; ", cookies), requestToken);
    }

    private static Task<HttpContext> PostDownloadAsync(TestServer server, string cookieHeader, string requestToken, string password)
    {
        var body = Encoding.UTF8.GetBytes(
            $"__RequestVerificationToken={Uri.EscapeDataString(requestToken)}&downloadPassword={Uri.EscapeDataString(password)}");
        return server.SendAsync(ctx =>
        {
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = $"/s/{Token}/download";
            ctx.Request.Headers.Cookie = cookieHeader;
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            ctx.Request.ContentLength = body.Length;
            ctx.Request.Body = new MemoryStream(body);
        });
    }

    private sealed class RecordingObjectStore(IObjectStore inner) : IObjectStore
    {
        public int OpenReads { get; private set; }
        public int InfoProbes { get; private set; }

        public Task PutFileAsync(string key, string localPath, string? contentType, CancellationToken ct) => inner.PutFileAsync(key, localPath, contentType, ct);
        public Task PutBytesAsync(string key, byte[] content, string? contentType, CancellationToken ct) => inner.PutBytesAsync(key, content, contentType, ct);
        public Task<ObjectInfo?> GetInfoAsync(string key, CancellationToken ct) { InfoProbes++; return inner.GetInfoAsync(key, ct); }
        public Task<ObjectStream?> OpenReadAsync(string key, CancellationToken ct) { OpenReads++; return inner.OpenReadAsync(key, ct); }
        public Task DownloadToFileAsync(string key, string localPath, CancellationToken ct) => inner.DownloadToFileAsync(key, localPath, ct);
        public Task DeleteAsync(string key, CancellationToken ct) => inner.DeleteAsync(key, ct);
        public Task DeletePrefixAsync(string prefix, CancellationToken ct) => inner.DeletePrefixAsync(prefix, ct);
        public Task CopyAsync(string sourceKey, string destinationKey, CancellationToken ct) => inner.CopyAsync(sourceKey, destinationKey, ct);
    }

    private sealed class NoopJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
