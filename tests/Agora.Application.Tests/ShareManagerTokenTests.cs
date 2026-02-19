using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
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
    [Fact]
    public async Task FindByTokenAsync_FindsShareByPlaintextToken()
    {
        await using var harness = await TestHarness.CreateAsync();
        var share = new Share
        {
            Id = Guid.NewGuid(),
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
        const string uploader = "uploader@example.com";
        using var fileStream = await harness.CreateUploadStreamAsync("document.txt", "hello");
        using var backgroundStream = await harness.CreateUploadStreamAsync("bg.png", "png-data");

        var stagedFile = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "document.txt",
            fileStream.Length,
            "text/plain",
            fileStream,
            CancellationToken.None);

        var stagedBackground = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "bg.png",
            backgroundStream.Length,
            "image/png",
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
        const string uploader = "uploader@example.com";
        using var backgroundStream = await harness.CreateUploadStreamAsync("bg.webp", "webp-data");

        var stagedBackground = await harness.Manager.StageUploadAsync(
            uploader,
            draftShareId,
            "bg.webp",
            backgroundStream.Length,
            "image/webp",
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

    private static CreateShareCommand CreateCommand(string token, UploadSourceFile file)
    {
        return new CreateShareCommand
        {
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

            // Use a unique temp storage root per test to avoid cross-test filesystem coupling.
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-sharemanager-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var appOptions = Options.Create(new AgoraOptions { StorageRoot = storageRoot });
            IShareContentStore contentStore = new ShareContentStore(appOptions);
            var manager = new ShareManager(
                db,
                appOptions,
                contentStore,
                new NoopBackgroundJobClient(),
                NullLogger<ShareManager>.Instance);

            return new TestHarness(connection, storageRoot, db, manager);
        }

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
