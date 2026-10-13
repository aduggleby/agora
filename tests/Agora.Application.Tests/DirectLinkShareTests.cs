using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>
/// Temporary direct links: a single inline-safe file served without an archive, purged at the first cleanup run
/// after expiry and never re-enabled.
/// </summary>
public sealed class DirectLinkShareTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();
    private const string OwnerEmail = "uploader@example.com";

    [Theory]
    [InlineData("30m", DirectLinkDuration.ThirtyMinutes, 30)]
    [InlineData(" 6H ", DirectLinkDuration.SixHours, 6 * 60)]
    [InlineData("1d", DirectLinkDuration.OneDay, 24 * 60)]
    [InlineData("7d", DirectLinkDuration.SevenDays, 7 * 24 * 60)]
    public void DirectLinkDurations_ParseTheFixedSet(string raw, DirectLinkDuration expected, int minutes)
    {
        Assert.True(DirectLinkDurations.TryParse(raw, out var duration));
        Assert.Equal(expected, duration);
        Assert.Equal(TimeSpan.FromMinutes(minutes), DirectLinkDurations.ToTimeSpan(duration));
        Assert.Equal(raw.Trim().ToLowerInvariant(), DirectLinkDurations.ToWireValue(duration));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2d")]
    [InlineData("30")]
    [InlineData("1y")]
    public void DirectLinkDurations_RejectAnythingElse(string? raw)
    {
        Assert.False(DirectLinkDurations.TryParse(raw, out _));
    }

    [Fact]
    public void ShareModes_DirectLinkIsNeitherPreviewNorZipDownload()
    {
        Assert.Equal(ShareAccessMode.DirectLink, ShareModes.ParseAccessMode("direct_link"));
        Assert.Equal("direct_link", ShareModes.ToStorageValue(ShareAccessMode.DirectLink));
        Assert.True(ShareModes.IsDirectLink("direct_link"));
        Assert.False(ShareModes.IsDirectLink("download_only"));
        Assert.False(ShareModes.AllowsPreview(ShareAccessMode.DirectLink));
        Assert.False(ShareModes.AllowsZipDownload(ShareAccessMode.DirectLink));
    }

    [Fact]
    public async Task CreateDirectLinkShareAsync_StoresTheFileWithoutAnArchive()
    {
        await using var harness = await Harness.CreateAsync();
        var draftShareId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var staged = await harness.StageAsync(draftShareId, "photo.png", "png-bytes");
        var before = DateTime.UtcNow;

        var result = await harness.Manager.CreateDirectLinkShareAsync(
            new CreateDirectLinkCommand(OwnerId, OwnerEmail, staged.UploadId, draftShareId, DirectLinkDuration.ThirtyMinutes),
            CancellationToken.None);

        var share = await harness.Db.Shares.Include(x => x.Files).SingleAsync(x => x.Id == result.ShareId);
        Assert.Equal("direct_link", share.AccessMode);
        Assert.Equal("none", share.NotifyMode);
        Assert.Equal(string.Empty, share.ZipDiskPath);
        Assert.Equal("photo.png", share.ZipDisplayName);
        Assert.Equal(9, share.ZipSizeBytes);
        Assert.Null(share.DownloadPasswordHash);
        Assert.Equal(8, result.Token.Length);
        Assert.NotNull(share.ExpiresAtUtc);
        Assert.InRange(share.ExpiresAtUtc!.Value, before.AddMinutes(30), DateTime.UtcNow.AddMinutes(30));
        var file = Assert.Single(share.Files);
        Assert.Equal("photo.png", file.OriginalFilename);
        Assert.Equal("image", file.RenderType);
        Assert.Equal("image/png", file.DetectedContentType);
        Assert.StartsWith("shares/", share.ContentRootPath, StringComparison.Ordinal);
        Assert.NotNull(await harness.ObjectStore.GetInfoAsync(file.StoredRelativePath!, CancellationToken.None));
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "zips")), "no archive is built for a direct link");
    }

    [Fact]
    public async Task CreateDirectLinkShareAsync_RefusesTwoFilesAndNonInlineTypes()
    {
        await using var harness = await Harness.CreateAsync();
        var twoFiles = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var first = await harness.StageAsync(twoFiles, "a.png", "one");
        await harness.StageAsync(twoFiles, "b.png", "two");

        var tooMany = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Manager.CreateDirectLinkShareAsync(
            new CreateDirectLinkCommand(OwnerId, OwnerEmail, first.UploadId, twoFiles, DirectLinkDuration.OneDay),
            CancellationToken.None));
        Assert.Contains("only one file", tooMany.Message, StringComparison.OrdinalIgnoreCase);

        var htmlDraft = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var html = await harness.StageAsync(htmlDraft, "page.html", "<html></html>");
        var notInline = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Manager.CreateDirectLinkShareAsync(
            new CreateDirectLinkCommand(OwnerId, OwnerEmail, html.UploadId, htmlDraft, DirectLinkDuration.OneDay),
            CancellationToken.None));
        Assert.Contains("only be downloaded", notInline.Message, StringComparison.OrdinalIgnoreCase);

        Assert.Empty(await harness.Db.Shares.ToListAsync());
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "shares")), "nothing durable was written");
    }

    [Fact]
    public async Task CreateDirectLinkShareAsync_RemovesTheStoredFileWhenTheRowCannotBeSaved()
    {
        await using var harness = await Harness.CreateAsync();
        var draftShareId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var staged = await harness.StageAsync(draftShareId, "clip.mp4", "mp4-bytes");
        // The owner check runs after the file is persisted, so a disabled owner exercises the compensation path.
        var owner = await harness.Db.Users.SingleAsync(x => x.Id == OwnerId);
        owner.IsEnabled = false;
        await harness.Db.SaveChangesAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Manager.CreateDirectLinkShareAsync(
            new CreateDirectLinkCommand(OwnerId, OwnerEmail, staged.UploadId, draftShareId, DirectLinkDuration.OneDay),
            CancellationToken.None));

        Assert.Empty(await harness.Db.Shares.ToListAsync());
        var sharesRoot = Path.Combine(harness.StorageRoot, "shares");
        var leftovers = Directory.Exists(sharesRoot) ? Directory.GetFiles(sharesRoot, "*", SearchOption.AllDirectories) : [];
        Assert.Empty(leftovers);
    }

    [Fact]
    public async Task CleanupExpiredSharesAsync_PurgesExpiredDirectLinksAtOnceAndKeepsTheGraceForOthers()
    {
        await using var harness = await Harness.CreateAsync();
        var now = DateTime.UtcNow;
        var directLink = NewShare("direct_link", now.AddMinutes(-1));
        var justExpired = NewShare("download_only", now.AddMinutes(-1));
        var longExpired = NewShare("download_only", now.AddDays(-8));
        var liveDirectLink = NewShare("direct_link", now.AddMinutes(10));
        harness.Db.Shares.AddRange(directLink, justExpired, longExpired, liveDirectLink);
        await harness.Db.SaveChangesAsync();

        var purged = await harness.Manager.CleanupExpiredSharesAsync(CancellationToken.None);

        Assert.Equal(2, purged);
        var byId = await harness.Db.Shares.AsNoTracking().ToDictionaryAsync(x => x.Id);
        Assert.NotNull(byId[directLink.Id].DeletedAtUtc);
        Assert.NotNull(byId[longExpired.Id].DeletedAtUtc);
        Assert.Null(byId[justExpired.Id].DeletedAtUtc);
        Assert.Null(byId[liveDirectLink.Id].DeletedAtUtc);
    }

    [Fact]
    public async Task CleanupExpiredSharesAsync_RemovesDirectLinkContentAtOnceAndOrdinaryContentAfterTheGrace()
    {
        await using var harness = await Harness.CreateAsync();
        var now = DateTime.UtcNow;
        var directRoot = $"shares/{now:yyyy}/{now:MM}/{Guid.NewGuid():N}";
        var ordinaryRoot = $"shares/{now:yyyy}/{now:MM}/{Guid.NewGuid():N}";
        var directKey = $"{directRoot}/photo.png";
        var ordinaryKey = $"{ordinaryRoot}/doc.txt";
        const string ordinaryZip = "zips/2026/10/ordinary.zip";
        await harness.ObjectStore.PutBytesAsync(directKey, "png"u8.ToArray(), "image/png", CancellationToken.None);
        await harness.ObjectStore.PutBytesAsync(ordinaryKey, "txt"u8.ToArray(), "text/plain", CancellationToken.None);
        await harness.ObjectStore.PutBytesAsync(ordinaryZip, "zip"u8.ToArray(), "application/zip", CancellationToken.None);

        var directLink = NewShare("direct_link", now.AddMinutes(-1));
        directLink.ContentRootPath = directRoot;
        directLink.Files.Add(new ShareFile { Id = Guid.NewGuid(), OriginalFilename = "photo.png", StoredRelativePath = directKey, RenderType = "image", OriginalSizeBytes = 3, DetectedContentType = "image/png" });
        var ordinary = NewShare("download_only", now.AddMinutes(-1));
        ordinary.ContentRootPath = ordinaryRoot;
        ordinary.ZipDiskPath = ordinaryZip;
        ordinary.Files.Add(new ShareFile { Id = Guid.NewGuid(), OriginalFilename = "doc.txt", StoredRelativePath = ordinaryKey, RenderType = "text", OriginalSizeBytes = 3, DetectedContentType = "text/plain" });
        harness.Db.Shares.AddRange(directLink, ordinary);
        await harness.Db.SaveChangesAsync();

        Assert.Equal(1, await harness.Manager.CleanupExpiredSharesAsync(CancellationToken.None));
        Assert.Null(await harness.ObjectStore.GetInfoAsync(directKey, CancellationToken.None));
        Assert.NotNull(await harness.ObjectStore.GetInfoAsync(ordinaryKey, CancellationToken.None));
        Assert.NotNull(await harness.ObjectStore.GetInfoAsync(ordinaryZip, CancellationToken.None));

        ordinary.ExpiresAtUtc = now.AddDays(-8);
        await harness.Db.SaveChangesAsync();
        Assert.Equal(1, await harness.Manager.CleanupExpiredSharesAsync(CancellationToken.None));
        Assert.Null(await harness.ObjectStore.GetInfoAsync(ordinaryKey, CancellationToken.None));
        Assert.Null(await harness.ObjectStore.GetInfoAsync(ordinaryZip, CancellationToken.None));
        Assert.All(await harness.Db.Shares.AsNoTracking().ToListAsync(), share => Assert.NotNull(share.DeletedAtUtc));
    }

    [Fact]
    public async Task ReenableShareFor24HoursAsync_RefusesDirectLinks()
    {
        await using var harness = await Harness.CreateAsync();
        var expired = NewShare("direct_link", DateTime.UtcNow.AddMinutes(-1));
        harness.Db.Shares.Add(expired);
        await harness.Db.SaveChangesAsync();

        var reenabled = await harness.Manager.ReenableShareFor24HoursAsync(expired.Id, ShareOwner.For(OwnerId, OwnerEmail), CancellationToken.None);

        Assert.False(reenabled);
        Assert.True((await harness.Db.Shares.AsNoTracking().SingleAsync(x => x.Id == expired.Id)).ExpiresAtUtc < DateTime.UtcNow);
    }

    private static Share NewShare(string accessMode, DateTime expiresAtUtc) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = OwnerId,
        UploaderEmail = OwnerEmail,
        ShareToken = Guid.NewGuid().ToString("N")[..8],
        ZipDisplayName = accessMode == "direct_link" ? "photo.png" : "files.zip",
        ZipDiskPath = string.Empty,
        ZipSizeBytes = 1,
        NotifyMode = "none",
        ShareExperienceType = "archive",
        AccessMode = accessMode,
        ExpiresAtUtc = expiresAtUtc,
        CreatedAtUtc = DateTime.UtcNow.AddDays(-9)
    };

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        public AgoraDbContext Db { get; }
        public ShareManager Manager { get; }
        public FileSystemObjectStore ObjectStore { get; }
        public string StorageRoot { get; }

        private Harness(SqliteConnection connection, string storageRoot, AgoraDbContext db, ShareManager manager, FileSystemObjectStore objectStore)
        {
            _connection = connection;
            StorageRoot = storageRoot;
            Db = db;
            Manager = manager;
            ObjectStore = objectStore;
        }

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(TestUsers.Seed(OwnerId, OwnerEmail));
            await db.SaveChangesAsync();

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-directlink-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var appOptions = Options.Create(new AgoraOptions { StorageRoot = storageRoot });
            var objectStore = new FileSystemObjectStore(storageRoot);
            var manager = new ShareManager(
                db,
                appOptions,
                new ShareContentStore(objectStore),
                objectStore,
                new NoopBackgroundJobClient(),
                new KeyedAsyncLock(),
                new ScratchSpaceMonitor(appOptions.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System),
                NullLogger<ShareManager>.Instance);

            return new Harness(connection, storageRoot, db, manager, objectStore);
        }

        public async Task<ShareManager.StagedUploadFile> StageAsync(string draftShareId, string fileName, string content)
        {
            var path = Path.Combine(StorageRoot, $"{Guid.NewGuid():N}-{fileName}");
            await File.WriteAllTextAsync(path, content);
            await using var stream = File.OpenRead(path);
            return await Manager.StageUploadAsync(OwnerId, draftShareId, fileName, stream.Length, stream, CancellationToken.None);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
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
}
