using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Hangfire;
using Agora.Application.Abstractions;
using Hangfire.Console;
using Hangfire.Server;
using Microsoft.Extensions.Options;

namespace Agora.Web.Services;

/// <summary>
/// Background job that validates staged uploads, creates a share, queues preview generation, and reports progress.
/// </summary>
public sealed class QueuedShareCreationJob(
    ShareManager manager,
    IBackgroundJobClient backgroundJobs,
    IEmailSender emailSender,
    ShareCreationStatusStore statusStore,
    ShareProgressBroadcaster broadcaster,
    IOptions<AgoraOptions> options,
    IOptions<EmailSenderOptions> emailSenderOptions,
    ILogger<QueuedShareCreationJob> logger)
{
    public sealed record Payload(
        string UploaderEmail,
        string DraftShareId,
        string ShareToken,
        string? Message,
        string? SenderName,
        string? SenderEmail,
        string? SenderMessage,
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
    private readonly EmailSenderOptions _emailSenderOptions = emailSenderOptions.Value;

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
        performContext?.WriteLine(
            $"Payload summary: uploader='{payload.UploaderEmail}', draftShareId='{payload.DraftShareId}', files={payload.UploadedFileIds.Count}, showPreviews={payload.ShowPreviews}, notifyMode='{payload.NotifyMode}', expiryMode='{payload.ExpiryMode}'.");
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
            performContext?.WriteLine($"Resolved {stagedUploads.Count} staged upload(s).");

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
            performContext?.WriteLine($"Validated staged upload size. totalBytes={totalBytes} maxTotal={_options.MaxTotalUploadBytes}.");

            if (totalBytes > _options.MaxTotalUploadBytes)
            {
                throw new InvalidOperationException("Total upload size exceeds limit.");
            }

            UploadSourceFile? templateBackgroundFile = null;
            if (!string.IsNullOrWhiteSpace(payload.TemplateBackgroundUploadId))
            {
                // Resolve template background from the dedicated upload purpose so it is never treated as share content.
                var stagedBackground = await manager.ResolveStagedUploadsAsync(
                    payload.UploaderEmail,
                    [payload.TemplateBackgroundUploadId.Trim()],
                    payload.DraftShareId,
                    ct,
                    ShareManager.UploadPurposeTemplateBackground);

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
            // Gallery mode requires image-only content; mixed sets fall back to archive mode.
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

            var result = await CreateShareWithRetryAsync(
                payload,
                templateBackgroundFile,
                uploadFiles,
                shareExperienceType,
                accessMode,
                expiryMode,
                templateMode,
                performContext,
                ct);

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
                var shareUrl = BuildShareUrl(result.Token);
                var email = BuildCompletionEmail(payload, shareUrl);
                await emailSender.SendAuthEmailAsync(email, ct);

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
            performContext?.WriteLine($"Exception type: {ex.GetType().FullName}");
            if (ex.InnerException is not null)
            {
                performContext?.WriteLine($"Inner exception: {ex.InnerException.GetType().FullName}: {ex.InnerException.Message}");
            }
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

    private static string? BuildSenderDetails(Payload payload)
    {
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(payload.SenderName))
        {
            lines.Add($"Sender name: {payload.SenderName.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(payload.SenderEmail))
        {
            lines.Add($"Sender email: {payload.SenderEmail.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(payload.SenderMessage))
        {
            lines.Add($"Message: {payload.SenderMessage.Trim()}");
        }

        return lines.Count == 0 ? null : string.Join('\n', lines);
    }

    private static AuthEmailMessage BuildCompletionEmailCore(Payload payload, string shareUrl, string configuredSenderDisplayName)
    {
        var senderIdentity = BuildSenderIdentity(payload);
        var senderMessage = (payload.SenderMessage ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(senderIdentity))
        {
            var normalizedDisplayName = string.IsNullOrWhiteSpace(configuredSenderDisplayName)
                ? "Agora"
                : configuredSenderDisplayName.Trim();
            var onBehalfOf = $"{normalizedDisplayName} on behalf of {senderIdentity}";
            var intro = !string.IsNullOrWhiteSpace(senderMessage)
                ? "The sender included this message:"
                : "The upload was processed and the files are ready to open.";
            var detail = !string.IsNullOrWhiteSpace(senderMessage)
                ? senderMessage
                : "No message was included.";
            return new AuthEmailMessage(
                To: payload.UploaderEmail,
                Subject: "Files were sent to you and processed",
                Preheader: "A sender uploaded files for you and processing is complete.",
                Headline: "New files were sent to you",
                IntroText: intro,
                DetailText: detail,
                ActionLabel: "Open share link",
                ActionUrl: shareUrl,
                SecondaryText: $"{onBehalfOf}. The upload has completed successfully.",
                FromDisplayNameOverride: onBehalfOf);
        }

        return new AuthEmailMessage(
            To: payload.UploaderEmail,
            Subject: "Your share link is ready",
            Preheader: "Your files finished processing and the share link is ready.",
            Headline: "Your share link is ready",
            IntroText: "Your upload has completed in the background.",
            DetailText: BuildSenderDetails(payload),
            ActionLabel: "Open share link",
            ActionUrl: shareUrl,
            SecondaryText: null);
    }

    private AuthEmailMessage BuildCompletionEmail(Payload payload, string shareUrl)
    {
        var configuredSenderDisplayName = (_emailSenderOptions.FromDisplayName ?? string.Empty).Trim();
        return BuildCompletionEmailCore(payload, shareUrl, configuredSenderDisplayName);
    }

    private static string BuildSenderIdentity(Payload payload)
    {
        var senderName = (payload.SenderName ?? string.Empty).Trim();
        var senderEmail = (payload.SenderEmail ?? string.Empty).Trim();
        if (senderName.Length > 0 && senderEmail.Length > 0)
        {
            return $"{senderName} ({senderEmail})";
        }

        if (senderName.Length > 0)
        {
            return senderName;
        }

        if (senderEmail.Length > 0)
        {
            return senderEmail;
        }

        return string.Empty;
    }

    private async Task<CreateShareResult> CreateShareWithRetryAsync(
        Payload payload,
        UploadSourceFile? templateBackgroundFile,
        IReadOnlyList<UploadSourceFile> uploadFiles,
        string shareExperienceType,
        string accessMode,
        ExpiryMode expiryMode,
        TemplateMode templateMode,
        PerformContext? performContext,
        CancellationToken ct)
    {
        var requestedToken = payload.ShareToken;

        for (var attempt = 0; attempt < 4; attempt += 1)
        {
            var attemptNo = attempt + 1;
            var attemptToken = requestedToken ?? "<auto>";
            performContext?.WriteLine($"Create-share attempt {attemptNo}/4 using token '{attemptToken}'.");
            try
            {
                if (requestedToken is not null)
                {
                    var before = await manager.GetShareTokenDiagnosticsAsync(requestedToken, ct);
                    performContext?.WriteLine(
                        $"Pre-attempt token diagnostics: exists={before.Exists} caseSensitiveMatches={before.CaseSensitiveMatchCount} caseInsensitiveMatches={before.CaseInsensitiveMatchCount} provider='{before.DatabaseProvider}' existingShareId='{before.ExistingShareId}' existingUploader='{before.ExistingShareUploader}'.");
                }

                return await manager.CreateShareAsync(new CreateShareCommand
                {
                    UploaderEmail = payload.UploaderEmail,
                    ShareToken = requestedToken,
                    Message = payload.Message,
                    SenderName = payload.SenderName,
                    SenderEmail = payload.SenderEmail,
                    SenderMessage = payload.SenderMessage,
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
            }
            catch (InvalidOperationException ex) when (
                requestedToken is not null &&
                ex.Message.Contains("already in use", StringComparison.OrdinalIgnoreCase) &&
                attempt < 3)
            {
                var collidedToken = requestedToken;
                var conflict = await manager.GetShareTokenDiagnosticsAsync(collidedToken, ct);
                requestedToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
                var replacement = await manager.GetShareTokenDiagnosticsAsync(requestedToken, ct);
                performContext?.WriteLine($"Share token collision detected; retrying with token '{requestedToken}'.");
                performContext?.WriteLine(
                    $"Collision diagnostics for '{collidedToken}': exists={conflict.Exists} caseSensitiveMatches={conflict.CaseSensitiveMatchCount} caseInsensitiveMatches={conflict.CaseInsensitiveMatchCount} existingShareId='{conflict.ExistingShareId}' existingUploader='{conflict.ExistingShareUploader}' createdAtUtc='{conflict.ExistingShareCreatedAtUtc}'.");
                performContext?.WriteLine(
                    $"Replacement token diagnostics for '{requestedToken}': exists={replacement.Exists} caseSensitiveMatches={replacement.CaseSensitiveMatchCount} caseInsensitiveMatches={replacement.CaseInsensitiveMatchCount} provider='{replacement.DatabaseProvider}'.");
                logger.LogWarning(
                    ex,
                    "Share token collision for queued token {Token}; retrying with {ReplacementToken}",
                    payload.ShareToken,
                    requestedToken);
            }
            catch (Exception ex)
            {
                performContext?.WriteLine($"Create-share attempt {attemptNo}/4 failed with non-collision error: {ex.GetType().FullName}: {ex.Message}");
                if (ex.InnerException is not null)
                {
                    performContext?.WriteLine($"Inner exception: {ex.InnerException.GetType().FullName}: {ex.InnerException.Message}");
                }

                throw;
            }
        }

        throw new InvalidOperationException("Unable to generate a unique share token right now.");
    }
}
