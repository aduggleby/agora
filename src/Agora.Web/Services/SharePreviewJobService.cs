using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Hangfire;
using Hangfire.Console;
using Hangfire.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Agora.Web.Services;

public sealed class SharePreviewJobService(
    AgoraDbContext db,
    IObjectStore objectStore,
    SharePreviewImageGenerator imageGenerator,
    IBackgroundJobClient backgroundJobs,
    IOptions<AgoraOptions> options,
    ILogger<SharePreviewJobService> logger)
{
    private const int PreviewRetryWindowMinutes = 5;
    private readonly AgoraOptions _options = options.Value;

    public sealed record Availability(string State, string PreviewKey, string? Reason);
    public sealed record ImagePayload(string State, byte[] Content, string ContentType, bool IsCacheable);

    public async Task QueueForShareAsync(Guid shareId, CancellationToken ct, PerformContext? performContext = null)
    {
        performContext?.WriteLine($"Queueing preview jobs for share '{shareId}'.");
        var fileIds = await db.ShareFiles
            .AsNoTracking()
            .Where(x => x.ShareId == shareId)
            .Select(x => x.Id)
            .ToListAsync(ct);

        foreach (var fileId in fileIds)
        {
            QueueGeneration(shareId, fileId);
        }
    }

    public void QueueGeneration(Guid shareId, Guid fileId)
    {
        backgroundJobs.Enqueue<SharePreviewJobService>(x => x.GeneratePreviewAsync(shareId, fileId, CancellationToken.None, null));
    }

    public async Task<Availability> GetAvailabilityAsync(Share share, ShareFile file, CancellationToken ct)
    {
        if (!CanGeneratePreview(file))
        {
            return new Availability("unavailable", string.Empty, "unsupported_type");
        }

        var previewKey = SharePreviewPaths.Key(share.Id, file.Id);
        if (await objectStore.GetInfoAsync(previewKey, ct) is not null)
        {
            return new Availability("ready", previewKey, null);
        }

        if (File.Exists(SharePreviewPaths.LockPath(_options.StorageRoot, share.Id, file.Id)))
        {
            return new Availability("pending", previewKey, null);
        }

        if (File.Exists(SharePreviewPaths.FailedPath(_options.StorageRoot, share.Id, file.Id)))
        {
            return new Availability("unavailable", previewKey, "generation_failed");
        }

        var windowEnd = share.CreatedAtUtc.AddMinutes(PreviewRetryWindowMinutes);
        return DateTime.UtcNow <= windowEnd
            ? new Availability("pending", previewKey, null)
            : new Availability("unavailable", previewKey, "generation_failed");
    }

    public async Task<ImagePayload> LoadPreviewImageAsync(Share share, ShareFile file, CancellationToken ct)
    {
        var availability = await GetAvailabilityAsync(share, file, ct);
        if (availability.State == "ready" && await ReadObjectAsync(availability.PreviewKey, ct) is { } content)
        {
            return new ImagePayload("ready", content, "image/jpeg", IsCacheable: true);
        }

        if (availability.State != "unavailable")
        {
            QueueGeneration(share.Id, file.Id);
            var pending = await imageGenerator.GeneratePendingPreviewAsync(ct);
            return new ImagePayload("pending", pending, "image/jpeg", IsCacheable: false);
        }

        var unavailable = await imageGenerator.GenerateUnavailablePreviewAsync(ct);
        return new ImagePayload("unavailable", unavailable, "image/jpeg", IsCacheable: false);
    }

    public async Task<ImagePayload> LoadThumbnailAsync(Share share, ShareFile file, CancellationToken ct)
    {
        if (await ReadObjectAsync(SharePreviewPaths.ThumbnailKey(share.Id, file.Id), ct) is { } content)
        {
            return new ImagePayload("ready", content, "image/jpeg", IsCacheable: true);
        }

        // Fall back to the standard preview
        return await LoadPreviewImageAsync(share, file, ct);
    }

    /// <summary>
    /// Source problems (over budget, undecodable, too slow) end in the <c>.failed</c> marker and are never retried;
    /// infrastructure failures (object store, IO, database) propagate so Hangfire retries exactly once.
    /// </summary>
    [Queue("previews")]
    [AutomaticRetry(Attempts = 1)]
    public async Task GeneratePreviewAsync(Guid shareId, Guid fileId, CancellationToken ct, PerformContext? performContext = null)
    {
        performContext?.WriteLine($"Generating preview for share '{shareId}', file '{fileId}'.");
        var file = await db.ShareFiles
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == fileId && x.ShareId == shareId, ct);
        if (file is null)
        {
            performContext?.WriteLine("Preview skipped: file not found.");
            return;
        }

        if (!CanGeneratePreview(file))
        {
            performContext?.WriteLine("Preview skipped: unsupported file type.");
            return;
        }

        if (!await IsShareActiveAsync(shareId, ct))
        {
            performContext?.WriteLine("Preview skipped: share missing or expired.");
            return;
        }

        var previewKey = SharePreviewPaths.Key(shareId, fileId);
        var thumbKey = SharePreviewPaths.ThumbnailKey(shareId, fileId);
        var previewExists = await objectStore.GetInfoAsync(previewKey, ct) is not null;
        var thumbnailMissing = ContentTypePolicy.IsRasterImage(file.OriginalFilename) && await objectStore.GetInfoAsync(thumbKey, ct) is null;
        if (previewExists && !thumbnailMissing)
        {
            performContext?.WriteLine("Preview already exists.");
            return;
        }

        var lockPath = SharePreviewPaths.LockPath(_options.StorageRoot, shareId, fileId);
        var failedPath = SharePreviewPaths.FailedPath(_options.StorageRoot, shareId, fileId);
        Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);

        FileStream? lockHandle = null;
        try
        {
            lockHandle = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }
        catch (IOException)
        {
            performContext?.WriteLine("Preview generation already in progress.");
            return;
        }

        var sourcePath = ScratchFiles.NewPath(_options.StorageRoot, Path.GetExtension(file.StoredRelativePath) ?? string.Empty);
        var published = false;
        // Download and generation share one time budget; uploads and cleanup run on the job's own token.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _options.Previews.TimeoutSeconds)));
        try
        {
            var sourceKey = ObjectKey.Normalize(file.StoredRelativePath);
            var sourceInfo = await objectStore.GetInfoAsync(sourceKey, budget.Token)
                ?? throw new PreviewSourceRejectedException("source object is missing");
            if (sourceInfo.Length > _options.Previews.MaxSourceBytes)
            {
                throw new PreviewSourceRejectedException(
                    $"source is {sourceInfo.Length} bytes, above the {_options.Previews.MaxSourceBytes} byte budget");
            }

            await objectStore.DownloadToFileAsync(sourceKey, sourcePath, budget.Token);

            if (!previewExists)
            {
                var content = await imageGenerator.GenerateForFileAsync(file, sourcePath, budget.Token);
                published = true;
                await objectStore.PutBytesAsync(previewKey, content, "image/jpeg", ct);
                performContext?.WriteLine("Preview generated.");
            }

            if (thumbnailMissing)
            {
                var thumbContent = await imageGenerator.GenerateMosaicThumbnailAsync(sourcePath, 300, budget.Token);
                published = true;
                await objectStore.PutBytesAsync(thumbKey, thumbContent, "image/jpeg", ct);
                performContext?.WriteLine("Mosaic thumbnail generated.");
            }

            if (File.Exists(failedPath))
            {
                File.Delete(failedPath);
            }
        }
        catch (PreviewSourceRejectedException ex)
        {
            await MarkRejectedAsync(ex.Message);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            await MarkRejectedAsync($"download and generation exceeded the {_options.Previews.TimeoutSeconds}s time budget");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Object store, IO or database trouble: leave no marker so the single Hangfire retry can succeed.
            logger.LogWarning(ex, "Failed generating preview for share={ShareId} file={FileId}", shareId, fileId);
            performContext?.WriteLine($"Preview generation failed: {ex.Message}");
            throw;
        }
        finally
        {
            if (published)
            {
                await RemovePreviewsIfShareGoneAsync(shareId, performContext);
            }

            ScratchFiles.TryDelete(sourcePath);
            lockHandle.Dispose();
            if (File.Exists(lockPath))
            {
                File.Delete(lockPath);
            }
        }

        // Expected for user-supplied content: not an error, never retried, and the message never includes content.
        async Task MarkRejectedAsync(string reason)
        {
            logger.LogInformation("Preview rejected for share={ShareId} file={FileId}: {Reason}", shareId, fileId, reason);
            performContext?.WriteLine($"Preview rejected: {reason}");
            await File.WriteAllTextAsync(failedPath, DateTime.UtcNow.ToString("O"), CancellationToken.None);
        }
    }

    /// <summary>
    /// Runs on every exit path once a preview upload was attempted: the share may have been deleted (and its previews
    /// purged) while this job ran, so remove what we wrote. Uses its own timeout so cancellation cannot skip it. If the
    /// check or purge fails, a retryable <see cref="DeleteSharePreviewsAsync"/> job takes over.
    /// </summary>
    private async Task RemovePreviewsIfShareGoneAsync(Guid shareId, PerformContext? performContext)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            if (!await IsShareActiveAsync(shareId, timeout.Token))
            {
                await objectStore.DeletePrefixAsync(SharePreviewPaths.Prefix(shareId), timeout.Token);
                performContext?.WriteLine("Share deleted or expired during generation; preview removed.");
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to remove previews of deleted share={ShareId}; queueing a retryable cleanup", shareId);
            try
            {
                backgroundJobs.Enqueue<SharePreviewJobService>(x => x.DeleteSharePreviewsAsync(shareId, CancellationToken.None));
            }
            catch (Exception enqueueEx)
            {
                logger.LogError(enqueueEx, "Failed to queue preview cleanup for share={ShareId}", shareId);
            }
        }
    }

    /// <summary>
    /// Idempotent, retryable cleanup of a deleted or expired share's previews (object prefix and local markers). A no-op
    /// for active shares; throws on failure so Hangfire retries.
    /// </summary>
    public async Task DeleteSharePreviewsAsync(Guid shareId, CancellationToken ct)
    {
        if (await IsShareActiveAsync(shareId, ct))
        {
            return;
        }

        await objectStore.DeletePrefixAsync(SharePreviewPaths.Prefix(shareId), ct);
        var markers = Path.Combine(_options.StorageRoot, "previews", shareId.ToString("N"));
        if (Directory.Exists(markers))
        {
            Directory.Delete(markers, recursive: true);
        }
    }

    private async Task<bool> IsShareActiveAsync(Guid shareId, CancellationToken ct)
    {
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(x => x.Id == shareId, ct);
        return share is not null && !ShareManager.IsExpired(share, DateTime.UtcNow);
    }

    private async Task<byte[]?> ReadObjectAsync(string key, CancellationToken ct)
    {
        var stored = await objectStore.OpenReadAsync(key, ct);
        if (stored is null)
        {
            return null;
        }

        await using (stored.Content)
        {
            using var buffer = new MemoryStream();
            await stored.Content.CopyToAsync(buffer, ct);
            return buffer.ToArray();
        }
    }

    private static bool CanGeneratePreview(ShareFile file)
    {
        var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();
        if (renderType is "image" or "pdf" or "text")
        {
            return true;
        }

        var extension = (Path.GetExtension(file.OriginalFilename) ?? string.Empty).Trim().ToLowerInvariant();
        return extension is ".pdf" or ".txt" or ".md" or ".csv" or ".json" or ".xml" or ".yaml" or ".yml" or ".log";
    }

}
