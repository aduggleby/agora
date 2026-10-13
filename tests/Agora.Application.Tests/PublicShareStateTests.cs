using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>
/// Deleted and expired shares are distinct public states (404 versus 410), and anonymous preview polling cannot
/// enqueue more than one generation job per retention window.
/// </summary>
public sealed class PublicShareStateTests
{
    [Fact]
    public void Deleted_and_expired_are_separate_states()
    {
        var now = new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);
        var live = new Share { ExpiresAtUtc = now.AddDays(1) };
        var expired = new Share { ExpiresAtUtc = now.AddMinutes(-1) };
        var deleted = new Share { ExpiresAtUtc = now.AddDays(1), DeletedAtUtc = now.AddMinutes(-5) };
        var deletedAndExpired = new Share { ExpiresAtUtc = now.AddMinutes(-1), DeletedAtUtc = now.AddMinutes(-5) };

        Assert.True(ShareManager.IsActive(live, now));
        Assert.False(ShareManager.IsDeleted(live));
        Assert.False(ShareManager.IsExpired(live, now));

        Assert.True(ShareManager.IsExpired(expired, now));
        Assert.False(ShareManager.IsDeleted(expired));
        Assert.False(ShareManager.IsActive(expired, now));

        Assert.True(ShareManager.IsDeleted(deleted));
        Assert.False(ShareManager.IsExpired(deleted, now));
        Assert.False(ShareManager.IsActive(deleted, now));

        Assert.True(ShareManager.IsDeleted(deletedAndExpired));
        Assert.True(ShareManager.IsExpired(deletedAndExpired, now));
    }

    [Fact]
    public void Indefinite_share_never_expires()
    {
        Assert.False(ShareManager.IsExpired(new Share { ExpiresAtUtc = null }, DateTime.UtcNow));
    }

    [Fact]
    public async Task Anonymous_preview_polling_enqueues_one_job_per_retention_window()
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();
        var pending = new SharePreviewJobService.Availability("pending", SharePreviewPaths.Key(share.Id, file.Id), null);

        harness.Service.QueueGenerationIfIdle(share, file, pending);
        harness.Service.QueueGenerationIfIdle(share, file, pending);
        harness.Service.QueueGenerationIfIdle(share, file, pending);

        Assert.Equal(1, harness.Jobs.Enqueued);
        var queuedPath = SharePreviewPaths.QueuedPath(harness.StorageRoot, share.Id, file.Id);
        Assert.True(File.Exists(queuedPath));

        // Once the marker is older than the retention window a new job may be queued.
        File.SetLastWriteTimeUtc(queuedPath, DateTime.UtcNow.AddHours(-(harness.RetentionHours + 1)));
        harness.Service.QueueGenerationIfIdle(share, file, pending);
        Assert.Equal(2, harness.Jobs.Enqueued);
    }

    [Theory]
    [InlineData(".lock")]
    [InlineData(".failed")]
    public async Task Anonymous_preview_polling_does_not_enqueue_while_a_marker_exists(string marker)
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();
        var markerPath = marker == ".lock"
            ? SharePreviewPaths.LockPath(harness.StorageRoot, share.Id, file.Id)
            : SharePreviewPaths.FailedPath(harness.StorageRoot, share.Id, file.Id);
        Directory.CreateDirectory(Path.GetDirectoryName(markerPath)!);
        await File.WriteAllTextAsync(markerPath, DateTime.UtcNow.ToString("O"));
        var pending = new SharePreviewJobService.Availability("pending", SharePreviewPaths.Key(share.Id, file.Id), null);

        harness.Service.QueueGenerationIfIdle(share, file, pending);

        Assert.Equal(0, harness.Jobs.Enqueued);
        Assert.False(File.Exists(SharePreviewPaths.QueuedPath(harness.StorageRoot, share.Id, file.Id)));
    }

    [Theory]
    [InlineData("ready", null)]
    [InlineData("unavailable", "unsupported_type")]
    public async Task Anonymous_preview_polling_does_not_enqueue_when_the_preview_exists_or_the_type_is_unsupported(string state, string? reason)
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();

        harness.Service.QueueGenerationIfIdle(share, file, new SharePreviewJobService.Availability(state, SharePreviewPaths.Key(share.Id, file.Id), reason));

        Assert.Equal(0, harness.Jobs.Enqueued);
    }

    [Fact]
    public async Task Concurrent_anonymous_polls_claim_the_marker_once_and_enqueue_one_job()
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();
        var pending = new SharePreviewJobService.Availability("pending", SharePreviewPaths.Key(share.Id, file.Id), null);

        using var start = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            start.Wait();
            harness.Service.QueueGenerationIfIdle(share, file, pending);
        })).ToArray();
        start.Set();
        await Task.WhenAll(tasks);

        Assert.Equal(1, harness.Jobs.Enqueued);
    }

    [Fact]
    public async Task A_marker_that_cannot_be_written_enqueues_nothing()
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();
        // A file where the marker directory must be created makes the claim fail; the enqueue must not happen.
        var markerDirectory = Path.GetDirectoryName(SharePreviewPaths.QueuedPath(harness.StorageRoot, share.Id, file.Id))!;
        Directory.CreateDirectory(Path.GetDirectoryName(markerDirectory)!);
        await File.WriteAllTextAsync(markerDirectory, "not a directory");

        harness.Service.QueueGenerationIfIdle(share, file, new SharePreviewJobService.Availability("pending", SharePreviewPaths.Key(share.Id, file.Id), null));

        Assert.Equal(0, harness.Jobs.Enqueued);
    }

    [Fact]
    public async Task A_missing_preview_shown_as_unavailable_is_recovered_once_per_retention_window()
    {
        await using var harness = await Harness.CreateAsync();
        // Created well outside the pending window, with no preview and no markers: the page shows "unavailable",
        // but the real availability calculation still lets one job be queued.
        var (share, file) = harness.NewShareFile(createdAtUtc: DateTime.UtcNow.AddHours(-2));

        var availability = await harness.Service.GetAvailabilityAsync(share, file, CancellationToken.None);
        Assert.Equal("unavailable", availability.State);
        Assert.Equal("generation_failed", availability.Reason);

        harness.Service.QueueGenerationIfIdle(share, file, availability);
        harness.Service.QueueGenerationIfIdle(share, file, await harness.Service.GetAvailabilityAsync(share, file, CancellationToken.None));
        Assert.Equal(1, harness.Jobs.Enqueued);

        var queuedPath = SharePreviewPaths.QueuedPath(harness.StorageRoot, share.Id, file.Id);
        File.SetLastWriteTimeUtc(queuedPath, DateTime.UtcNow.AddHours(-(harness.RetentionHours + 1)));
        harness.Service.QueueGenerationIfIdle(share, file, await harness.Service.GetAvailabilityAsync(share, file, CancellationToken.None));
        Assert.Equal(2, harness.Jobs.Enqueued);

        // A rejected source is never recovered by polling.
        await File.WriteAllTextAsync(SharePreviewPaths.FailedPath(harness.StorageRoot, share.Id, file.Id), DateTime.UtcNow.ToString("O"));
        File.SetLastWriteTimeUtc(queuedPath, DateTime.UtcNow.AddHours(-(harness.RetentionHours + 1)));
        harness.Service.QueueGenerationIfIdle(share, file, await harness.Service.GetAvailabilityAsync(share, file, CancellationToken.None));
        Assert.Equal(2, harness.Jobs.Enqueued);
    }

    [Fact]
    public async Task Unconditional_queueing_writes_the_queued_marker_so_the_first_poll_does_not_duplicate_it()
    {
        await using var harness = await Harness.CreateAsync();
        var (share, file) = harness.NewShareFile();

        harness.Service.QueueGeneration(share.Id, file.Id);
        harness.Service.QueueGenerationIfIdle(share, file, new SharePreviewJobService.Availability("pending", SharePreviewPaths.Key(share.Id, file.Id), null));

        Assert.Equal(1, harness.Jobs.Enqueued);
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly AgoraDbContext _db;

        private Harness(SqliteConnection connection, AgoraDbContext db, string storageRoot, int retentionHours, CountingJobClient jobs, SharePreviewJobService service)
        {
            _connection = connection;
            _db = db;
            StorageRoot = storageRoot;
            RetentionHours = retentionHours;
            Jobs = jobs;
            Service = service;
        }

        public string StorageRoot { get; }
        public int RetentionHours { get; }
        public CountingJobClient Jobs { get; }
        public SharePreviewJobService Service { get; }

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-preview-gate-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = Options.Create(new AgoraOptions { StorageRoot = storageRoot, ZombieUploadRetentionHours = 24 });
            var jobs = new CountingJobClient();
            var service = new SharePreviewJobService(
                db,
                new FileSystemObjectStore(storageRoot),
                new SharePreviewImageGenerator(options),
                jobs,
                options,
                NullLogger<SharePreviewJobService>.Instance);

            return new Harness(connection, db, storageRoot, options.Value.ZombieUploadRetentionHours, jobs, service);
        }

        public (Share Share, ShareFile File) NewShareFile(DateTime? createdAtUtc = null)
        {
            var share = new Share { Id = Guid.NewGuid(), CreatedAtUtc = createdAtUtc ?? DateTime.UtcNow };
            var file = new ShareFile { Id = Guid.NewGuid(), ShareId = share.Id, Share = share, OriginalFilename = "photo.jpg", RenderType = "image" };
            return (share, file);
        }

        public async ValueTask DisposeAsync()
        {
            await _db.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(StorageRoot))
            {
                Directory.Delete(StorageRoot, recursive: true);
            }
        }
    }

    private sealed class CountingJobClient : IBackgroundJobClient
    {
        private int _enqueued;

        public int Enqueued => Volatile.Read(ref _enqueued);

        public string Create(Job job, IState state)
        {
            Interlocked.Increment(ref _enqueued);
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
