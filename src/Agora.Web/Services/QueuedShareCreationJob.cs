using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Hangfire;
using Agora.Application.Abstractions;
using Hangfire.Console;
using Hangfire.Server;
using Microsoft.Extensions.Options;

namespace Agora.Web.Services;

public sealed class QueuedShareCreationJob(
    ShareManager manager,
    IBackgroundJobClient backgroundJobs,
    IEmailSender emailSender,
    ShareCreationStatusStore statusStore,
    ShareProgressBroadcaster broadcaster,
    IOptions<AgoraOptions> options,
    ILogger<QueuedShareCreationJob> logger)
{
    public sealed record Payload(
        string UploaderEmail,
        string DraftShareId,
        string ShareToken,
        string? Message,
        string? DownloadPassword,
        bool ShowPreviews,
        string? ZipFileName,
        string NotifyMode,
        string ExpiryMode,
        DateTime? ExpiresAtUtc,
        string TemplateMode,
        string? TemplateTitle,
        string? TemplateH1,
        string? TemplateDescription,
        string? TemplateBackgroundColorHex,
        string? TemplateContainerPosition,
        string? TemplateBackgroundUploadId,
        IReadOnlyList<string> UploadedFileIds);

    private readonly AgoraOptions _options = options.Value;

    public string Queue(Payload payload)
    {
        var jobId = backgroundJobs.Enqueue<QueuedShareCreationJob>(x => x.ProcessAsync(payload, CancellationToken.None, null));
        var queued = statusStore.MarkQueued(payload.ShareToken, payload.UploaderEmail, jobId);
        _ = broadcaster.BroadcastAsync(queued);
        return jobId;
    }

    public async Task ProcessAsync(Payload payload, CancellationToken ct, PerformContext? performContext = null)
    {
        var token = payload.ShareToken;
        performContext?.WriteLine($"Starting queued share creation for token '{token}'.");
        var processing = statusStore.MarkProcessing(token);
        await broadcaster.BroadcastAsync(processing, ct);

        try
        {
            var validateActive = statusStore.UpdateStep(token, "validate", "active", "Validating queued request...");
            performContext?.WriteLine("Validating queued request...");
            await broadcaster.BroadcastAsync(validateActive, ct);

            var stagedUploads = await manager.ResolveStagedUploadsAsync(
                payload.UploaderEmail,
                payload.UploadedFileIds,
                payload.DraftShareId,
                ct);

            var validateDone = statusStore.UpdateStep(token, "validate", "completed");
            await broadcaster.BroadcastAsync(validateDone, ct);

            if (stagedUploads.Count == 0)
            {
                throw new InvalidOperationException("At least one uploaded file is required.");
            }

            if (stagedUploads.Count > _options.MaxFilesPerShare)
            {
                throw new InvalidOperationException($"Too many files. Max {_options.MaxFilesPerShare}.");
            }

            long totalBytes = 0;
            foreach (var staged in stagedUploads)
            {
                if (staged.OriginalSizeBytes > _options.MaxFileSizeBytes)
                {
                    throw new InvalidOperationException($"File '{staged.OriginalFileName}' exceeds max size.");
                }

                totalBytes += staged.OriginalSizeBytes;
            }

            if (totalBytes > _options.MaxTotalUploadBytes)
            {
                throw new InvalidOperationException("Total upload size exceeds limit.");
            }

            UploadSourceFile? templateBackgroundFile = null;
            if (!string.IsNullOrWhiteSpace(payload.TemplateBackgroundUploadId))
            {
                var stagedBackground = await manager.ResolveStagedUploadsAsync(
                    payload.UploaderEmail,
                    [payload.TemplateBackgroundUploadId.Trim()],
                    payload.DraftShareId,
                    ct);

                var resolved = stagedBackground.SingleOrDefault();
                if (resolved is not null)
                {
                    templateBackgroundFile = new UploadSourceFile(
                        TempPath: resolved.TempPath,
                        OriginalFileName: resolved.OriginalFileName,
                        OriginalSizeBytes: resolved.OriginalSizeBytes,
                        ContentType: resolved.ContentType);
                }
            }

            var uploadFiles = stagedUploads
                .Select(staged => new UploadSourceFile(
                    TempPath: staged.TempPath,
                    OriginalFileName: staged.OriginalFileName,
                    OriginalSizeBytes: staged.OriginalSizeBytes,
                    ContentType: staged.ContentType))
                .ToList();

            var allFilesAreImages = uploadFiles.All(file => LooksLikeImage(file.OriginalFileName, file.ContentType));
            var shareExperienceType = payload.ShowPreviews && allFilesAreImages ? "gallery" : "archive";
            var accessMode = payload.ShowPreviews ? "preview_and_download" : "download_only";
            var expiryMode = string.Equals(payload.ExpiryMode, "indefinite", StringComparison.OrdinalIgnoreCase)
                ? ExpiryMode.Indefinite
                : ExpiryMode.Date;
            var templateMode = string.Equals(payload.TemplateMode, "per_upload", StringComparison.OrdinalIgnoreCase)
                ? TemplateMode.PerUpload
                : TemplateMode.AccountDefault;

            var createActive = statusStore.UpdateStep(token, "create_share", "active", "Building archive and saving share...");
            performContext?.WriteLine("Building archive and creating share...");
            await broadcaster.BroadcastAsync(createActive, ct);

            var result = await manager.CreateShareAsync(new CreateShareCommand
            {
                UploaderEmail = payload.UploaderEmail,
                ShareToken = payload.ShareToken,
                Message = payload.Message,
                DownloadPassword = payload.DownloadPassword,
                ShareExperienceType = shareExperienceType,
                AccessMode = accessMode,
                ZipFileName = payload.ZipFileName,
                ExpiryMode = expiryMode,
                ExpiresAtUtc = payload.ExpiresAtUtc,
                NotifyMode = payload.NotifyMode,
                TemplateMode = templateMode,
                TemplateTitle = payload.TemplateTitle,
                TemplateH1 = payload.TemplateH1,
                TemplateDescription = payload.TemplateDescription,
                TemplateBackgroundImageUrl = string.Empty,
                TemplateBackgroundColorHex = payload.TemplateBackgroundColorHex,
                TemplateContainerPosition = payload.TemplateContainerPosition,
                TemplateBackgroundFile = templateBackgroundFile,
                Files = uploadFiles
            }, ct);

            var createDone = statusStore.UpdateStep(token, "create_share", "completed");
            await broadcaster.BroadcastAsync(createDone, ct);

            try
            {
                foreach (var directoryPath in stagedUploads.Select(x => x.DirectoryPath).Distinct(StringComparer.Ordinal))
                {
                    if (Directory.Exists(directoryPath))
                    {
                        Directory.Delete(directoryPath, recursive: true);
                    }
                }
            }
            catch (Exception cleanupEx)
            {
                logger.LogWarning(cleanupEx, "Unable to delete one or more staged upload directories for token {Token}", payload.ShareToken);
            }

            await manager.DeleteDraftShareAsync(payload.UploaderEmail, payload.DraftShareId, ct);
            if (payload.ShowPreviews)
            {
                var queuePreviewsActive = statusStore.UpdateStep(token, "queue_previews", "active", "Queuing preview generation...");
                performContext?.WriteLine("Queuing preview generation...");
                await broadcaster.BroadcastAsync(queuePreviewsActive, ct);
            }
            else
            {
                var queuePreviewsSkipped = statusStore.UpdateStep(token, "queue_previews", "completed", "Skipped (previews disabled).");
                await broadcaster.BroadcastAsync(queuePreviewsSkipped, ct);
            }

            if (payload.ShowPreviews)
            {
                backgroundJobs.Enqueue<SharePreviewJobService>(x => x.QueueForShareAsync(result.ShareId, CancellationToken.None, null));
                var queuePreviewsDone = statusStore.UpdateStep(token, "queue_previews", "completed");
                await broadcaster.BroadcastAsync(queuePreviewsDone, ct);
            }

            var notifyActive = statusStore.UpdateStep(token, "notify_uploader", "active", "Sending ready-link email...");
            performContext?.WriteLine("Sending ready-link email to uploader...");
            await broadcaster.BroadcastAsync(notifyActive, ct);

            try
            {
                var shareUrl = BuildShareUrl(payload.ShareToken);
                await emailSender.SendAuthEmailAsync(new AuthEmailMessage(
                    To: payload.UploaderEmail,
                    Subject: "Your share link is ready",
                    Preheader: "Your files finished processing and the share link is ready.",
                    Headline: "Your share link is ready",
                    IntroText: "You can leave the page while processing; this email confirms your link is now ready to share.",
                    DetailText: "Your upload has completed in the background.",
                    ActionLabel: "Open share link",
                    ActionUrl: shareUrl,
                    SecondaryText: "If you are already on the status page, it will update automatically."),
                    ct);

                var notifyDone = statusStore.UpdateStep(token, "notify_uploader", "completed");
                performContext?.WriteLine("Ready-link email sent.");
                await broadcaster.BroadcastAsync(notifyDone, ct);
            }
            catch (Exception emailEx)
            {
                logger.LogWarning(emailEx, "Share-ready email failed for token {Token}", payload.ShareToken);
                performContext?.WriteLine($"Ready-link email failed: {emailEx.Message}");
                var notifyFailed = statusStore.UpdateStep(token, "notify_uploader", "completed", "Email delivery failed. You can still copy the link here.");
                await broadcaster.BroadcastAsync(notifyFailed, ct);
            }

            var done = statusStore.MarkCompleted(token);
            performContext?.WriteLine($"Completed queued share creation for token '{token}'.");
            await broadcaster.BroadcastAsync(done, ct);

            logger.LogInformation(
                "Completed queued share creation token={Token} shareId={ShareId} uploader={Uploader}",
                payload.ShareToken,
                result.ShareId,
                payload.UploaderEmail);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Queued share creation failed for token {Token}", token);
            performContext?.WriteLine($"Queued share creation failed: {ex.Message}");
            var failed = statusStore.MarkFailed(token, ex.Message);
            await broadcaster.BroadcastAsync(failed, ct);
        }
    }

    private static bool LooksLikeImage(string? fileName, string? contentType)
    {
        var normalizedContentType = (contentType ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedContentType.StartsWith("image/", StringComparison.Ordinal))
        {
            return true;
        }

        var extension = (Path.GetExtension(fileName ?? string.Empty) ?? string.Empty).Trim().ToLowerInvariant();
        return extension is ".jpg" or ".jpeg" or ".png" or ".gif" or ".webp" or ".bmp" or ".svg";
    }

    private string BuildShareUrl(string token)
    {
        var configuredBase = (_options.PublicBaseUrl ?? string.Empty).Trim().TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(configuredBase))
        {
            return $"{configuredBase}/s/{token}";
        }

        return $"/s/{token}";
    }
}
