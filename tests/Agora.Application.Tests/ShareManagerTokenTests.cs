using Agora.Application.Abstractions;
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
/// Covers share-token lookup/uniqueness behavior and staged-upload purpose isolation in <see cref="ShareManager"/>.
/// </summary>
public sealed class ShareManagerTokenTests
{
    private static readonly Guid UploaderId = Guid.NewGuid();

    [Fact]
    public async Task FindByTokenAsync_FindsShareByPlaintextToken()
    {
        await using var harness = await TestHarness.CreateAsync();
        var share = new Share
        {
            Id = Guid.NewGuid(),
            OwnerUserId = UploaderId,
            UploaderEmail = "uploader@example.com",
            ShareToken = "Token_123",
            ZipDisplayName = "files.zip",
            ZipDiskPath = "zips/2026/02/test.zip",
            ZipSizeBytes = 123,
            NotifyMode = "none",
            ShareExperienceType = "archive",
            AccessMode = "download_only",
            CreatedAtUtc = DateTime.UtcNow
        };
        harness.Db.Shares.Add(share);
        await harness.Db.SaveChangesAsync();

        var found = await harness.Manager.FindByTokenAsync("Token_123", CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(share.Id, found.Id);
    }

    [Fact]
    public async Task IsShareTokenAvailableAsync_ReturnsFalseWhenTokenExists()
    {
        await using var harness = await TestHarness.CreateAsync();
        harness.Db.Shares.Add(new Share
        {
            Id = Guid.NewGuid(),
            OwnerUserId = UploaderId,
            UploaderEmail = "uploader@example.com",
            ShareToken = "existing_token",
            ZipDisplayName = "files.zip",
            ZipDiskPath = "zips/2026/02/test.zip",
            ZipSizeBytes = 123,
            NotifyMode = "none",
            ShareExperienceType = "archive",
            AccessMode = "download_only",
            CreatedAtUtc = DateTime.UtcNow
        });
        await harness.Db.SaveChangesAsync();

        var isTakenAvailable = await harness.Manager.IsShareTokenAvailableAsync("existing_token", CancellationToken.None);
        var isFreshAvailable = await harness.Manager.IsShareTokenAvailableAsync("new_token", CancellationToken.None);

        Assert.False(isTakenAvailable);
        Assert.True(isFreshAvailable);
    }

    [Fact]
    public async Task CreateShareAsync_WhenRequestedTokenAlreadyExists_Throws()
    {
        await using var harness = await TestHarness.CreateAsync();
        var firstFile = await harness.CreateUploadFileAsync("first.txt", "one");
        var secondFile = await harness.CreateUploadFileAsync("second.txt", "two");

        await harness.Manager.CreateShareAsync(
            CreateCommand("dup_token", firstFile),
            CancellationToken.None);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.Manager.CreateShareAsync(CreateCommand("dup_token", secondFile), CancellationToken.None));

        Assert.Contains("already in use", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ListStagedUploadsForDraftAsync_ExcludesTemplateBackgroundUploads()
    {
        await using var harness = await TestHarness.CreateAsync();
        const string draftShareId = "11111111111111111111111111111111";
        var uploader = UploaderId;
        await harness.Manager.EnsureDraftShareAsync(uploader, draftShareId, CancellationToken.None);
        using var fileStream = await harness.CreateUploadStreamAsync("document.txt", "hello");
        using var backgroundStream = await harness.CreateUploadStreamAsync("bg.png", "png-data");

        var stagedFile = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "document.txt",
            fileStream.Length,
            fileStream,
            CancellationToken.None);

        var stagedBackground = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "bg.png",
            backgroundStream.Length,
            backgroundStream,
            CancellationToken.None,
            ShareManager.UploadPurposeTemplateBackground);

        var listed = await harness.Manager.ListStagedUploadsForDraftAsync(uploader, draftShareId, CancellationToken.None);

        var fileUpload = Assert.Single(listed);
        Assert.Equal(stagedFile.UploadId, fileUpload.UploadId);
        Assert.DoesNotContain(listed, x => x.UploadId == stagedBackground.UploadId);
        Assert.Contains(Path.Combine("uploads", "staged-template-backgrounds"), stagedBackground.DirectoryPath, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolveStagedUploadsAsync_RejectsTemplateBackgroundAsShareFile()
    {
        await using var harness = await TestHarness.CreateAsync();
        const string draftShareId = "22222222222222222222222222222222";
        var uploader = UploaderId;
        await harness.Manager.EnsureDraftShareAsync(uploader, draftShareId, CancellationToken.None);
        using var backgroundStream = await harness.CreateUploadStreamAsync("bg.webp", "webp-data");

        var stagedBackground = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "bg.webp",
            backgroundStream.Length,
            backgroundStream,
            CancellationToken.None,
            ShareManager.UploadPurposeTemplateBackground);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.Manager.ResolveStagedUploadsAsync(
                uploader,
                [stagedBackground.UploadId],
                draftShareId,
                CancellationToken.None));

        var resolvedBackground = await harness.Manager.ResolveStagedUploadsAsync(
            uploader,
            [stagedBackground.UploadId],
            draftShareId,
            CancellationToken.None,
            ShareManager.UploadPurposeTemplateBackground);

        Assert.Single(resolvedBackground);
    }

    [Fact]
    public async Task StageUploadAsync_DerivesContentTypeFromExtensionOnly()
    {
        await using var harness = await TestHarness.CreateAsync();
        const string draftShareId = "33333333333333333333333333333333";
        var uploader = UploaderId;
        await harness.Manager.EnsureDraftShareAsync(uploader, draftShareId, CancellationToken.None);
        using var htmlAsPng = await harness.CreateUploadStreamAsync("evil.png", "<script>alert(1)</script>");
        using var htmlFile = await harness.CreateUploadStreamAsync("page.html", "<html></html>");
        using var noExtension = await harness.CreateUploadStreamAsync("README", "plain");

        var stagedPng = await harness.Manager.StageUploadAsync(uploader, draftShareId, "evil.png", htmlAsPng.Length, htmlAsPng, CancellationToken.None);
        var stagedHtml = await harness.Manager.StageUploadAsync(uploader, draftShareId, "page.html", htmlFile.Length, htmlFile, CancellationToken.None);
        var stagedBinary = await harness.Manager.StageUploadAsync(uploader, draftShareId, "README", noExtension.Length, noExtension, CancellationToken.None);

        Assert.Equal("image/png", stagedPng.ContentType);
        Assert.Equal("text/html", stagedHtml.ContentType);
        Assert.Equal("application/octet-stream", stagedBinary.ContentType);

        // The persisted metadata round-trips the derived type as well.
        var resolved = await harness.Manager.ResolveStagedUploadsAsync(uploader, [stagedPng.UploadId], draftShareId, CancellationToken.None);
        Assert.Equal("image/png", Assert.Single(resolved).ContentType);
    }

    [Fact]
    public async Task CreateShareAsync_StoresExtensionDerivedContentTypeAndRenderType()
    {
        await using var harness = await TestHarness.CreateAsync();
        // Caller-supplied content type is text/plain (see CreateUploadFileAsync); the stored values ignore it.
        var htmlFile = await harness.CreateUploadFileAsync("page.html", "<html></html>");
        var pngFile = await harness.CreateUploadFileAsync("photo.png", "not-really-png");
        var svgFile = await harness.CreateUploadFileAsync("logo.svg", "<svg/>");

        var command = new CreateShareCommand
        {
            OwnerUserId = UploaderId,
            UploaderEmail = "uploader@example.com",
            ShareToken = "content_type_token",
            NotifyMode = "none",
            ExpiryMode = ExpiryMode.Date,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
            TemplateMode = TemplateMode.AccountDefault,
            Files = [htmlFile, pngFile, svgFile]
        };
        var result = await harness.Manager.CreateShareAsync(command, CancellationToken.None);

        var share = await harness.Db.Shares.Include(x => x.Files).SingleAsync(x => x.Id == result.ShareId);
        var byName = share.Files.ToDictionary(x => x.OriginalFilename, StringComparer.Ordinal);
        Assert.Equal("text/html", byName["page.html"].DetectedContentType);
        Assert.Equal("html", byName["page.html"].RenderType);
        Assert.Equal("image/png", byName["photo.png"].DetectedContentType);
        Assert.Equal("image", byName["photo.png"].RenderType);
        Assert.Equal("image/svg+xml", byName["logo.svg"].DetectedContentType);
        Assert.Equal("svg", byName["logo.svg"].RenderType);
    }

    private static CreateShareCommand CreateCommand(string token, UploadSourceFile file)
    {
        return new CreateShareCommand
        {
            OwnerUserId = UploaderId,
            UploaderEmail = "uploader@example.com",
            ShareToken = token,
            NotifyMode = "none",
            ExpiryMode = ExpiryMode.Date,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
            TemplateMode = TemplateMode.AccountDefault,
            Files = [file]
        };
    }

    private sealed class TestHarness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _storageRoot;

        public AgoraDbContext Db { get; }
        public ShareManager Manager { get; }

        private TestHarness(SqliteConnection connection, string storageRoot, AgoraDbContext db, ShareManager manager)
        {
            _connection = connection;
            _storageRoot = storageRoot;
            Db = db;
            Manager = manager;
        }

        public static async Task<TestHarness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<AgoraDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new AgoraDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(TestUsers.Seed(UploaderId, "uploader@example.com"));
            await db.SaveChangesAsync();

            // Use a unique temp storage root per test to avoid cross-test filesystem coupling.
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-sharemanager-tests", Guid.NewGuid().ToString("N"));
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
                UnlimitedScratch(appOptions.Value),
                NullLogger<ShareManager>.Instance);

            return new TestHarness(connection, storageRoot, db, manager);
        }

        // Temp volumes can be small; the scratch budget is tested on its own with injected providers.
        private static ScratchSpaceMonitor UnlimitedScratch(AgoraOptions options) =>
            new(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);

        public async Task<UploadSourceFile> CreateUploadFileAsync(string fileName, string content)
        {
            var uploadPath = Path.Combine(_storageRoot, $"{Guid.NewGuid():N}-{fileName}");
            await File.WriteAllTextAsync(uploadPath, content);
            var info = new FileInfo(uploadPath);
            return new UploadSourceFile(uploadPath, fileName, info.Length, "text/plain");
        }

        public async Task<FileStream> CreateUploadStreamAsync(string fileName, string content)
        {
            var uploadPath = Path.Combine(_storageRoot, $"{Guid.NewGuid():N}-{fileName}");
            await File.WriteAllTextAsync(uploadPath, content);
            return File.OpenRead(uploadPath);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state)
        {
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState)
        {
            return true;
        }
    }
}
