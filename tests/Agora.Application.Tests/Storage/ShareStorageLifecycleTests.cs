using System.Net;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Endpoints;
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
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace Agora.Application.Tests.Storage;

/// <summary>
/// Object-store lifecycle around shares: compensation of failed creations, deletion of every share-owned object,
/// previews written after a concurrent delete, encrypted-archive plaintext cleanup and the scratch sweep.
/// </summary>
public sealed class ShareStorageLifecycleTests : IAsyncLifetime
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "agora-lifecycle-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly FailingSaveInterceptor _saveInterceptor = new();
    private AgoraDbContext _db = null!;
    private RecordingObjectStore _store = null!;

    private string StorageRoot => Path.Combine(_root, "storage");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(StorageRoot);
        await _connection.OpenAsync();
        _db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>()
            .UseSqlite(_connection)
            .AddInterceptors(_saveInterceptor)
            .Options);
        await _db.Database.EnsureCreatedAsync();
        _store = new RecordingObjectStore(new FileSystemObjectStore(StorageRoot));
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
        Directory.Delete(_root, recursive: true);
    }

    [Fact]
    public async Task Failed_database_save_removes_every_uploaded_object_and_scratch_file()
    {
        var command = await CommandAsync(password: "secret", withBackground: true);
        _saveInterceptor.Fail = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateManager().CreateShareAsync(command, Ct));

        Assert.Contains(_store.Written, key => key.StartsWith("shares/", StringComparison.Ordinal));
        Assert.Contains(_store.Written, key => key.EndsWith(".agz", StringComparison.Ordinal));
        Assert.Contains(_store.Written, key => key.Contains("-background", StringComparison.Ordinal));
        AssertNoDurableObjects();
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Failed_upload_midway_removes_objects_written_before_it()
    {
        _store.FailOn = key => key.Contains("-background", StringComparison.Ordinal);

        await Assert.ThrowsAsync<IOException>(async () => await CreateManager().CreateShareAsync(await CommandAsync(password: null, withBackground: true), Ct));

        Assert.Contains(_store.Written, key => key.EndsWith(".zip", StringComparison.Ordinal));
        AssertNoDurableObjects();
        AssertScratchEmpty();
        Assert.Empty(_db.Shares.AsNoTracking());
    }

    [Fact]
    public async Task Cancellation_during_creation_still_compensates()
    {
        using var cts = new CancellationTokenSource();
        _store.OnWrite = key =>
        {
            if (key.StartsWith("zips/", StringComparison.Ordinal))
            {
                cts.Cancel();
            }
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await CreateManager().CreateShareAsync(await CommandAsync(password: null, withBackground: true), cts.Token));

        AssertNoDurableObjects();
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Deleting_a_share_removes_archive_content_background_and_previews_only()
    {
        var manager = CreateManager();
        await _store.PutBytesAsync("uploads/templates/general/account.png", [1], null, Ct);
        var result = await manager.CreateShareAsync(await CommandAsync(password: null, withBackground: true), Ct);
        var other = await manager.CreateShareAsync(await CommandAsync(password: null, withBackground: false), Ct);
        await _store.PutBytesAsync(SharePreviewPaths.Key(result.ShareId, Guid.NewGuid()), [1], null, Ct);
        await _store.PutBytesAsync(SharePreviewPaths.Key(other.ShareId, Guid.NewGuid()), [1], null, Ct);

        await manager.DeleteShareFilesAsync(result.ShareId, Ct);

        var share = await _db.Shares.AsNoTracking().SingleAsync(x => x.Id == result.ShareId);
        Assert.Null(await _store.GetInfoAsync(share.ZipDiskPath, Ct));
        Assert.Null(await _store.GetInfoAsync(ObjectKey.FromInternalMarker(share.BackgroundImageUrl)!, Ct));
        Assert.False(Directory.Exists(Path.Combine(StorageRoot, share.ContentRootPath!)));
        Assert.False(Directory.Exists(Path.Combine(StorageRoot, "previews", result.ShareId.ToString("N"))));
        Assert.True(Directory.Exists(Path.Combine(StorageRoot, "previews", other.ShareId.ToString("N"))));
        Assert.NotNull(await _store.GetInfoAsync("uploads/templates/general/account.png", Ct));
        var otherShare = await _db.Shares.AsNoTracking().SingleAsync(x => x.Id == other.ShareId);
        Assert.NotNull(await _store.GetInfoAsync(otherShare.ZipDiskPath, Ct));
    }

    [Fact]
    public async Task Preview_written_after_a_concurrent_delete_is_removed()
    {
        var result = await CreateManager().CreateShareAsync(await CommandAsync(password: null, withBackground: false, imageFile: true), Ct);
        var file = await _db.ShareFiles.AsNoTracking().SingleAsync(x => x.ShareId == result.ShareId);
        // Simulates the share being deleted while the preview job runs, right after the preview upload.
        _store.OnWrite = key =>
        {
            if (key == SharePreviewPaths.Key(result.ShareId, file.Id))
            {
                _db.Shares.Where(x => x.Id == result.ShareId).ExecuteUpdate(s => s.SetProperty(x => x.DeletedAtUtc, DateTime.UtcNow));
            }
        };

        await CreatePreviewService().GeneratePreviewAsync(result.ShareId, file.Id, Ct);

        Assert.Contains(SharePreviewPaths.Key(result.ShareId, file.Id), _store.Written);
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(result.ShareId, file.Id), Ct));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(result.ShareId, file.Id), Ct));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, result.ShareId, file.Id)));
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Preview_generation_uploads_preview_and_thumbnail_for_active_share()
    {
        var result = await CreateManager().CreateShareAsync(await CommandAsync(password: null, withBackground: false, imageFile: true), Ct);
        var share = await _db.Shares.AsNoTracking().Include(x => x.Files).SingleAsync(x => x.Id == result.ShareId);
        var file = share.Files.Single();
        var service = CreatePreviewService();

        await service.GeneratePreviewAsync(result.ShareId, file.Id, Ct);

        Assert.Equal("ready", (await service.GetAvailabilityAsync(share, file, Ct)).State);
        Assert.Equal("ready", (await service.LoadThumbnailAsync(share, file, Ct)).State);
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Encrypted_download_deletes_plaintext_on_wrong_password_and_on_failure_before_response()
    {
        var encrypted = await EncryptAsync("payload", "right");
        var context = new DefaultHttpContext();

        Assert.Null(await EncryptedArchiveDownload.ServeAsync(context, new MemoryStream(encrypted), "wrong", StorageRoot, "a.zip", () => Task.CompletedTask, Ct));
        AssertScratchEmpty();

        await Assert.ThrowsAsync<InvalidOperationException>(() => EncryptedArchiveDownload.ServeAsync(
            context, new MemoryStream(encrypted), "right", StorageRoot, "a.zip", () => throw new InvalidOperationException("db down"), Ct));
        AssertScratchEmpty();

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EncryptedArchiveDownload.ServeAsync(
            context, new MemoryStream(encrypted), "right", StorageRoot, "a.zip", () => Task.CompletedTask, cancelled.Token));
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Encrypted_download_serves_plaintext_and_deletes_it_after_the_response()
    {
        var encrypted = await EncryptAsync("zip-bytes", "right");
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapPost("/download", async (HttpContext context, CancellationToken ct) =>
            await EncryptedArchiveDownload.ServeAsync(context, new MemoryStream(encrypted), "right", StorageRoot, "a.zip", () => Task.CompletedTask, ct));
        await app.StartAsync();

        var response = await app.GetTestClient().PostAsync("/download", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("zip-bytes", await response.Content.ReadAsStringAsync());
        for (var i = 0; i < 50 && Directory.EnumerateFiles(ScratchFiles.Root(StorageRoot)).Any(); i++)
        {
            await Task.Delay(20);
        }

        AssertScratchEmpty();
    }

    [Fact]
    public async Task Zombie_cleanup_sweeps_stale_scratch_files_and_preview_locks_but_keeps_directories()
    {
        var scratch = ScratchFiles.Root(StorageRoot);
        var aspnet = Directory.CreateDirectory(Path.Combine(scratch, "aspnet")).FullName;
        var stale = new[] { Path.Combine(scratch, "old.zip"), Path.Combine(aspnet, "old.tmp"), Path.Combine(StorageRoot, "previews", "abc", "x.jpg.lock") };
        var fresh = new[] { Path.Combine(scratch, "new.zip"), Path.Combine(StorageRoot, "previews", "abc", "y.jpg.lock") };
        var durable = Path.Combine(StorageRoot, "previews", "abc", "z.jpg");
        foreach (var path in stale.Concat(fresh).Append(durable))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, "x");
        }

        foreach (var path in stale.Append(durable))
        {
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-3));
        }

        await CreateManager().CleanupZombieUploadsAsync(Ct);

        Assert.All(stale, path => Assert.False(File.Exists(path)));
        Assert.All(fresh, path => Assert.True(File.Exists(path)));
        Assert.True(File.Exists(durable));
        Assert.True(Directory.Exists(aspnet));
    }

    [Fact]
    public async Task Committed_share_keeps_its_objects_when_the_save_reports_failure()
    {
        var command = await CommandAsync(password: null, withBackground: true);
        _saveInterceptor.FailAfterCommit = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateManager().CreateShareAsync(command, Ct));

        _saveInterceptor.FailAfterCommit = false;
        var share = await _db.Shares.AsNoTracking().Include(x => x.Files).SingleAsync();
        Assert.Empty(_store.DeleteAttempts);
        Assert.NotNull(await _store.GetInfoAsync(share.ZipDiskPath, Ct));
        Assert.NotNull(await _store.GetInfoAsync(share.Files.Single().StoredRelativePath!, Ct));
        Assert.NotNull(await _store.GetInfoAsync(ObjectKey.FromInternalMarker(share.BackgroundImageUrl)!, Ct));
        AssertScratchEmpty();
    }

    [Theory]
    [InlineData("prefix")]
    [InlineData("archive")]
    public async Task Compensation_attempts_every_deletion_when_one_fails(string failing)
    {
        var command = await CommandAsync(password: null, withBackground: true);
        _saveInterceptor.Fail = true;
        _store.FailDeleteOn = target => failing == "prefix"
            ? target.StartsWith("shares/", StringComparison.Ordinal)
            : target.EndsWith(".zip", StringComparison.Ordinal);

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateManager().CreateShareAsync(command, Ct));

        // Content prefix, archive and background are each attempted; only the injected failure is left behind.
        Assert.Contains(_store.DeleteAttempts, x => x.StartsWith("shares/", StringComparison.Ordinal));
        Assert.Contains(_store.DeleteAttempts, x => x.EndsWith(".zip", StringComparison.Ordinal));
        var backgroundKey = Assert.Single(_store.Written, x => x.Contains("-background", StringComparison.Ordinal));
        Assert.Contains(backgroundKey, _store.DeleteAttempts);
        Assert.Null(await _store.GetInfoAsync(backgroundKey, Ct));
        var zipKey = Assert.Single(_store.Written, x => x.EndsWith(".zip", StringComparison.Ordinal));
        Assert.Equal(failing == "archive", await _store.GetInfoAsync(zipKey, Ct) is not null);
    }

    [Fact]
    public async Task Preview_cleanup_runs_when_thumbnail_fails_after_a_concurrent_delete()
    {
        var (shareId, file) = await CreateImageShareAsync();
        DeleteShareAfterPreviewUpload(shareId, file.Id);
        _store.FailOn = key => key == SharePreviewPaths.ThumbnailKey(shareId, file.Id);

        // The upload failure is an infrastructure error, so it propagates (Hangfire retries once) after cleanup ran.
        await Assert.ThrowsAsync<IOException>(() => CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, Ct));

        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, shareId, file.Id)));
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Transient_upload_failure_propagates_for_retry_without_a_failed_marker()
    {
        var (shareId, file) = await CreateImageShareAsync();
        _store.FailOn = key => key == SharePreviewPaths.Key(shareId, file.Id);

        await Assert.ThrowsAsync<IOException>(() => CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, Ct));

        Assert.False(File.Exists(SharePreviewPaths.FailedPath(StorageRoot, shareId, file.Id)));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, shareId, file.Id)));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        AssertScratchEmpty();

        // The retry succeeds once the store recovers.
        _store.FailOn = _ => false;
        await CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, Ct);
        Assert.NotNull(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.NotNull(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
    }

    [Fact]
    public async Task Missing_thumbnail_is_generated_when_the_preview_already_exists()
    {
        var (shareId, file) = await CreateImageShareAsync();
        var existingPreview = new byte[] { 1, 2, 3 };
        await _store.PutBytesAsync(SharePreviewPaths.Key(shareId, file.Id), existingPreview, "image/jpeg", Ct);

        await CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, Ct);

        Assert.NotNull(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
        var preview = await _store.OpenReadAsync(SharePreviewPaths.Key(shareId, file.Id), Ct);
        Assert.NotNull(preview);
        await using (preview.Content)
        {
            using var buffer = new MemoryStream();
            await preview.Content.CopyToAsync(buffer, Ct);
            Assert.Equal(existingPreview, buffer.ToArray());
        }

        AssertScratchEmpty();
    }

    [Fact]
    public async Task Source_above_the_byte_budget_is_rejected_before_download()
    {
        var (shareId, file) = await CreateImageShareAsync();
        var downloads = 0;
        _store.OnDownload = _ => downloads++;
        var service = CreatePreviewService(previews: new AgoraPreviewOptions { MaxSourceBytes = 10 });

        await service.GeneratePreviewAsync(shareId, file.Id, Ct);

        Assert.Equal(0, downloads);
        Assert.True(File.Exists(SharePreviewPaths.FailedPath(StorageRoot, shareId, file.Id)));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Preview_cleanup_runs_when_the_job_is_cancelled_after_a_concurrent_delete()
    {
        var (shareId, file) = await CreateImageShareAsync();
        using var cts = new CancellationTokenSource();
        DeleteShareAfterPreviewUpload(shareId, file.Id, cts.Cancel);

        var error = await Record.ExceptionAsync(() => CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, cts.Token));

        Assert.True(error is null or OperationCanceledException, error?.ToString());
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, shareId, file.Id)));
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Failed_preview_cleanup_queues_a_retryable_job_that_removes_the_previews()
    {
        var (shareId, file) = await CreateImageShareAsync();
        DeleteShareAfterPreviewUpload(shareId, file.Id);
        _store.FailDeleteOn = target => target == SharePreviewPaths.Prefix(shareId);
        var jobs = new NoopBackgroundJobClient();

        await CreatePreviewService(jobs).GeneratePreviewAsync(shareId, file.Id, Ct);

        Assert.Contains(SharePreviewPaths.Prefix(shareId), _store.DeleteAttempts);
        Assert.NotNull(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, shareId, file.Id)));
        AssertScratchEmpty();
        var job = Assert.Single(jobs.Created);
        Assert.Equal(nameof(SharePreviewJobService.DeleteSharePreviewsAsync), job.Method.Name);
        Assert.Equal(shareId, job.Args[0]);

        // Still failing: the job throws so Hangfire retries it.
        await Assert.ThrowsAsync<IOException>(() => CreatePreviewService().DeleteSharePreviewsAsync(shareId, Ct));

        _store.FailDeleteOn = _ => false;
        await CreatePreviewService().DeleteSharePreviewsAsync(shareId, Ct);
        await CreatePreviewService().DeleteSharePreviewsAsync(shareId, Ct);

        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
        Assert.False(Directory.Exists(Path.Combine(StorageRoot, "previews", shareId.ToString("N"))));
    }

    [Fact]
    public async Task Preview_source_over_budget_is_marked_failed_without_throwing()
    {
        var (shareId, file) = await CreateImageShareAsync();
        var share = await _db.Shares.AsNoTracking().SingleAsync(x => x.Id == shareId);
        // The test image is 40x30 = 1200 pixels.
        var service = CreatePreviewService(previews: new AgoraPreviewOptions { MaxSourcePixels = 1000 });

        await service.GeneratePreviewAsync(shareId, file.Id, Ct);

        Assert.True(File.Exists(SharePreviewPaths.FailedPath(StorageRoot, shareId, file.Id)));
        Assert.False(File.Exists(SharePreviewPaths.LockPath(StorageRoot, shareId, file.Id)));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
        var availability = await service.GetAvailabilityAsync(share, file, Ct);
        Assert.Equal("unavailable", availability.State);
        Assert.Equal("generation_failed", availability.Reason);
        AssertScratchEmpty();
    }

    [Fact]
    public async Task Preview_cleanup_job_is_a_no_op_for_an_active_share()
    {
        var (shareId, file) = await CreateImageShareAsync();
        await CreatePreviewService().GeneratePreviewAsync(shareId, file.Id, Ct);
        _store.DeleteAttempts.Clear();

        await CreatePreviewService().DeleteSharePreviewsAsync(shareId, Ct);

        Assert.Empty(_store.DeleteAttempts);
        Assert.NotNull(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
    }

    [Fact]
    public async Task Gif_source_is_marked_failed_without_throwing()
    {
        var (shareId, file) = await CreateImageShareAsync("anim.gif");
        var share = await _db.Shares.AsNoTracking().SingleAsync(x => x.Id == shareId);
        var service = CreatePreviewService();

        await service.GeneratePreviewAsync(shareId, file.Id, Ct);

        Assert.True(File.Exists(SharePreviewPaths.FailedPath(StorageRoot, shareId, file.Id)));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.Key(shareId, file.Id), Ct));
        Assert.Null(await _store.GetInfoAsync(SharePreviewPaths.ThumbnailKey(shareId, file.Id), Ct));
        Assert.Equal("generation_failed", (await service.GetAvailabilityAsync(share, file, Ct)).Reason);
        AssertScratchEmpty();
    }

    private async Task<(Guid ShareId, ShareFile File)> CreateImageShareAsync(string imageName = "photo.png")
    {
        var result = await CreateManager().CreateShareAsync(await CommandAsync(password: null, withBackground: false, imageFile: true, imageName), Ct);
        return (result.ShareId, await _db.ShareFiles.AsNoTracking().SingleAsync(x => x.ShareId == result.ShareId));
    }

    /// <summary>Simulates the share being deleted (previews purged) right after the preview upload.</summary>
    private void DeleteShareAfterPreviewUpload(Guid shareId, Guid fileId, Action? then = null) =>
        _store.OnWrite = key =>
        {
            if (key == SharePreviewPaths.Key(shareId, fileId))
            {
                _db.Shares.Where(x => x.Id == shareId).ExecuteUpdate(s => s.SetProperty(x => x.DeletedAtUtc, DateTime.UtcNow));
                then?.Invoke();
            }
        };

    private ShareManager CreateManager() => new(
        _db,
        Options.Create(new AgoraOptions { StorageRoot = StorageRoot }),
        new ShareContentStore(_store),
        _store,
        new NoopBackgroundJobClient(),
        NullLogger<ShareManager>.Instance);

    private SharePreviewJobService CreatePreviewService(IBackgroundJobClient? jobs = null, AgoraPreviewOptions? previews = null)
    {
        var options = Options.Create(new AgoraOptions { StorageRoot = StorageRoot, Previews = previews ?? new AgoraPreviewOptions() });
        return new SharePreviewJobService(
            _db,
            _store,
            new SharePreviewImageGenerator(options),
            jobs ?? new NoopBackgroundJobClient(),
            options,
            NullLogger<SharePreviewJobService>.Instance);
    }

    private async Task<CreateShareCommand> CommandAsync(string? password, bool withBackground, bool imageFile = false, string imageName = "photo.png")
    {
        var uploads = Directory.CreateDirectory(Path.Combine(_root, "uploads")).FullName;
        var filePath = Path.Combine(uploads, $"{Guid.NewGuid():N}");
        UploadSourceFile file;
        if (imageFile)
        {
            using var image = new Image<Rgba32>(40, 30, new Rgba32(200, 100, 50));
            var isGif = imageName.EndsWith(".gif", StringComparison.OrdinalIgnoreCase);
            if (isGif)
            {
                await image.SaveAsGifAsync(filePath);
            }
            else
            {
                await image.SaveAsPngAsync(filePath);
            }

            file = new UploadSourceFile(filePath, imageName, new FileInfo(filePath).Length, isGif ? "image/gif" : "image/png");
        }
        else
        {
            await File.WriteAllTextAsync(filePath, "hello");
            file = new UploadSourceFile(filePath, "hello.txt", 5, "text/plain");
        }

        UploadSourceFile? background = null;
        if (withBackground)
        {
            var backgroundPath = Path.Combine(uploads, $"{Guid.NewGuid():N}");
            await File.WriteAllBytesAsync(backgroundPath, [1, 2, 3]);
            background = new UploadSourceFile(backgroundPath, "bg.png", 3, "image/png");
        }

        return new CreateShareCommand
        {
            UploaderEmail = "uploader@example.com",
            DownloadPassword = password,
            NotifyMode = "none",
            ExpiryMode = ExpiryMode.Date,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
            TemplateMode = withBackground ? TemplateMode.PerUpload : TemplateMode.AccountDefault,
            TemplateBackgroundFile = background,
            Files = [file]
        };
    }

    private static async Task<byte[]> EncryptAsync(string content, string password)
    {
        using var input = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(content));
        using var output = new MemoryStream();
        await ZipEncryption.EncryptAsync(input, output, password, Ct);
        return output.ToArray();
    }

    private void AssertNoDurableObjects()
    {
        foreach (var area in new[] { "shares", "zips", "previews" })
        {
            var path = Path.Combine(StorageRoot, area);
            Assert.True(!Directory.Exists(path) || !Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Any(), $"{area} is not empty");
        }
    }

    private void AssertScratchEmpty()
    {
        var scratch = ScratchFiles.Root(StorageRoot);
        Assert.True(!Directory.Exists(scratch) || !Directory.EnumerateFiles(scratch, "*", SearchOption.AllDirectories).Any(), "scratch is not empty");
    }

    private sealed class FailingSaveInterceptor : SaveChangesInterceptor
    {
        public bool Fail { get; set; }

        /// <summary>Lets the save commit, then reports a failure (a lost acknowledgement).</summary>
        public bool FailAfterCommit { get; set; }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) =>
            Fail ? throw new InvalidOperationException("Injected save failure.") : base.SavingChangesAsync(eventData, result, cancellationToken);

        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default) =>
            FailAfterCommit ? throw new InvalidOperationException("Injected failure after commit.") : base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    /// <summary>Records written keys and can fail or run a callback on specific writes.</summary>
    private sealed class RecordingObjectStore(IObjectStore inner) : IObjectStore
    {
        public List<string> Written { get; } = [];
        public List<string> DeleteAttempts { get; } = [];
        public Func<string, bool> FailOn { get; set; } = _ => false;
        public Func<string, bool> FailDeleteOn { get; set; } = _ => false;
        public Action<string> OnWrite { get; set; } = _ => { };

        public async Task PutFileAsync(string key, string localPath, string? contentType, CancellationToken ct)
        {
            BeforeWrite(key);
            await inner.PutFileAsync(key, localPath, contentType, ct);
            AfterWrite(key);
        }

        public async Task PutBytesAsync(string key, byte[] content, string? contentType, CancellationToken ct)
        {
            BeforeWrite(key);
            await inner.PutBytesAsync(key, content, contentType, ct);
            AfterWrite(key);
        }

        public async Task CopyAsync(string sourceKey, string destinationKey, CancellationToken ct)
        {
            BeforeWrite(destinationKey);
            await inner.CopyAsync(sourceKey, destinationKey, ct);
            AfterWrite(destinationKey);
        }

        public Task<ObjectInfo?> GetInfoAsync(string key, CancellationToken ct) => inner.GetInfoAsync(key, ct);
        public Task<ObjectStream?> OpenReadAsync(string key, CancellationToken ct) => inner.OpenReadAsync(key, ct);
        public Action<string> OnDownload { get; set; } = _ => { };

        public Task DownloadToFileAsync(string key, string localPath, CancellationToken ct)
        {
            OnDownload(key);
            return inner.DownloadToFileAsync(key, localPath, ct);
        }
        public Task DeleteAsync(string key, CancellationToken ct) => BeforeDelete(key) ?? inner.DeleteAsync(key, ct);
        public Task DeletePrefixAsync(string prefix, CancellationToken ct) => BeforeDelete(prefix) ?? inner.DeletePrefixAsync(prefix, ct);

        private Task? BeforeDelete(string target)
        {
            DeleteAttempts.Add(target);
            return FailDeleteOn(target) ? Task.FromException(new IOException($"Injected delete failure for {target}.")) : null;
        }

        private void BeforeWrite(string key)
        {
            if (FailOn(key))
            {
                throw new IOException($"Injected upload failure for {key}.");
            }
        }

        private void AfterWrite(string key)
        {
            Written.Add(key);
            OnWrite(key);
        }
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public List<Job> Created { get; } = [];

        public string Create(Job job, IState state)
        {
            Created.Add(job);
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
