using Agora.Application.Abstractions;
using Agora.Application.Models;
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
    IShareContentStore contentStore,
    SharePreviewImageGenerator imageGenerator,
    IBackgroundJobClient backgroundJobs,
    IOptions<AgoraOptions> options,
    ILogger<SharePreviewJobService> logger)
{
    private const int PreviewRetryWindowMinutes = 5;
    private readonly AgoraOptions _options = options.Value;

    public sealed record Availability(string State, string PreviewPath, string? Reason);
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

    public Availability GetAvailability(Share share, ShareFile file)
    {
        if (!CanGeneratePreview(file))
        {
            return new Availability("unavailable", string.Empty, "unsupported_type");
        }

        var previewPath = SharePreviewPaths.Absolute(_options.StorageRoot, share.Id, file.Id);
        var lockPath = GetLockPath(previewPath);
        var failedPath = GetFailedPath(previewPath);

        if (File.Exists(previewPath))
        {
            return new Availability("ready", previewPath, null);
        }

        if (File.Exists(lockPath))
        {
            return new Availability("pending", previewPath, null);
        }

        if (File.Exists(failedPath))
        {
            return new Availability("unavailable", previewPath, "generation_failed");
        }

        var windowEnd = share.CreatedAtUtc.AddMinutes(PreviewRetryWindowMinutes);
        return DateTime.UtcNow <= windowEnd
            ? new Availability("pending", previewPath, null)
            : new Availability("unavailable", previewPath, "generation_failed");
    }

    public async Task<ImagePayload> LoadPreviewImageAsync(Share share, ShareFile file, CancellationToken ct)
    {
        var availability = GetAvailability(share, file);
        if (availability.State == "ready")
        {
            var content = await File.ReadAllBytesAsync(availability.PreviewPath, ct);
            return new ImagePayload("ready", content, "image/jpeg", IsCacheable: true);
        }

        if (availability.State == "pending")
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
        var thumbPath = SharePreviewPaths.ThumbnailAbsolute(_options.StorageRoot, share.Id, file.Id);
        if (File.Exists(thumbPath))
        {
            var content = await File.ReadAllBytesAsync(thumbPath, ct);
            return new ImagePayload("ready", content, "image/jpeg", IsCacheable: true);
        }

        // Fall back to the standard preview
        return await LoadPreviewImageAsync(share, file, ct);
    }

    [Queue("previews")]
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

        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(x => x.Id == shareId, ct);
        if (share is null || ShareManager.IsExpired(share, DateTime.UtcNow))
        {
            performContext?.WriteLine("Preview skipped: share missing or expired.");
            return;
        }

        var previewPath = SharePreviewPaths.Absolute(_options.StorageRoot, shareId, fileId);
        if (File.Exists(previewPath))
        {
            performContext?.WriteLine("Preview already exists.");
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(previewPath)!);
        var lockPath = GetLockPath(previewPath);
        var failedPath = GetFailedPath(previewPath);

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

        try
        {
            var absoluteSourcePath = contentStore.ResolveAbsolutePath(file.StoredRelativePath);
            if (absoluteSourcePath is null || !File.Exists(absoluteSourcePath))
            {
                throw new InvalidOperationException("Source file is unavailable.");
            }

            var content = await imageGenerator.GenerateForFileAsync(file, absoluteSourcePath, ct);
            var tempPath = previewPath + ".tmp";
            await File.WriteAllBytesAsync(tempPath, content, ct);
            File.Move(tempPath, previewPath, overwrite: true);
            performContext?.WriteLine("Preview generated.");

            var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();
            if (renderType == "image")
            {
                var thumbPath = SharePreviewPaths.ThumbnailAbsolute(_options.StorageRoot, shareId, fileId);
                if (!File.Exists(thumbPath))
                {
                    var thumbContent = await imageGenerator.GenerateMosaicThumbnailAsync(absoluteSourcePath, 300, ct);
                    var thumbTempPath = thumbPath + ".tmp";
                    await File.WriteAllBytesAsync(thumbTempPath, thumbContent, ct);
                    File.Move(thumbTempPath, thumbPath, overwrite: true);
                    performContext?.WriteLine("Mosaic thumbnail generated.");
                }
            }
            if (File.Exists(failedPath))
            {
                File.Delete(failedPath);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed generating preview for share={ShareId} file={FileId}", shareId, fileId);
            performContext?.WriteLine($"Preview generation failed: {ex.Message}");
            await File.WriteAllTextAsync(failedPath, DateTime.UtcNow.ToString("O"), ct);
        }
        finally
        {
            lockHandle.Dispose();
            if (File.Exists(lockPath))
            {
                File.Delete(lockPath);
            }
        }
    }

    private static string GetLockPath(string previewPath) => previewPath + ".lock";
    private static string GetFailedPath(string previewPath) => previewPath + ".failed";

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
