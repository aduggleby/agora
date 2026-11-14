using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;

namespace Agora.Web.Services;

/// <summary>A public uploader's submission, raw as sent (the service trims and validates the fields).</summary>
public sealed record PublicShareRequest(
    string UploadToken,
    string DraftShareId,
    string SenderName,
    string SenderEmail,
    string SenderMessage,
    IEnumerable<string?> UploadedFileIds,
    /// <summary>A share link to use instead of a generated one; only the E2E host passes it.</summary>
    string? ShareTokenOverride = null);

/// <summary>
/// Validation and payload building of a public upload submission. Submitting never opens a draft: the draft is only
/// looked up, so it does not count against the open-draft caps.
/// </summary>
public static class PublicShareSubmission
{
    public static async Task<PreparedShare> PrepareAsync(
        AuthService authService,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        AgoraOptions cfg,
        PublicShareRequest request,
        CancellationToken ct)
    {
        var uploadToken = request.UploadToken.Trim();
        var draftShareId = request.DraftShareId.Trim();
        // Sender text is stored (SenderName 200, SenderEmail 320 columns) and shown on the page and in mail.
        var senderName = SenderFields.NormalizeText(request.SenderName);
        var senderEmail = EmailAddress.Normalize(SenderFields.NormalizeText(request.SenderEmail));
        var senderMessage = request.SenderMessage.Trim();
        if (string.IsNullOrWhiteSpace(uploadToken) || string.IsNullOrWhiteSpace(draftShareId))
        {
            return Refuse(ShareRefusal.BadRequest("uploadToken and draftShareId are required."));
        }

        if (string.IsNullOrWhiteSpace(senderName))
        {
            return Refuse(ShareRefusal.BadRequest("senderName is required."));
        }

        if (senderName.Length > 200)
        {
            return Refuse(ShareRefusal.BadRequest("senderName must be at most 200 characters."));
        }

        if (senderMessage.Length > 2000)
        {
            return Refuse(ShareRefusal.BadRequest("senderMessage must be at most 2000 characters."));
        }

        if (senderEmail.Length > 320 || !SenderFields.IsValidEmailAddress(senderEmail))
        {
            return Refuse(ShareRefusal.BadRequest("senderEmail must be a valid email address."));
        }

        var user = await authService.FindByUploadTokenAsync(uploadToken, ct);
        if (user is null)
        {
            return Refuse(new ShareRefusal(StatusCodes.Status404NotFound, "Upload link not found."));
        }

        var uploadedFileIds = request.UploadedFileIds
            .Select(x => x?.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToArray();

        // Refused before the draft is opened or looked at.
        if (uploadedFileIds.Length == 0)
        {
            return Refuse(ShareRefusal.BadRequest("At least one file is required."));
        }

        try
        {
            // Lookup only: submitting never opens a draft (and never counts against the open-draft caps).
            draftShareId = await manager.FindPublicUploadDraftAsync(user.Id, draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Refuse(ShareRefusal.BadRequest(ex.Message));
        }
        catch (UploadLimitException ex)
        {
            return Refuse(ShareRefusal.From(ex));
        }

        IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads;
        try
        {
            stagedUploads = await manager.ResolveStagedUploadsAsync(user.Id, uploadedFileIds, draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Refuse(ShareRefusal.BadRequest(ex.Message));
        }

        if (stagedUploads.Count == 0)
        {
            return Refuse(ShareRefusal.BadRequest("At least one file is required."));
        }

        if (stagedUploads.Count > cfg.MaxFilesPerShare)
        {
            return Refuse(ShareRefusal.BadRequest($"Too many files. Max {cfg.MaxFilesPerShare}."));
        }

        var total = 0L;
        foreach (var staged in stagedUploads)
        {
            if (staged.OriginalSizeBytes > cfg.MaxFileSizeBytes)
            {
                return Refuse(ShareRefusal.BadRequest($"File '{staged.OriginalFileName}' exceeds max size."));
            }

            total += staged.OriginalSizeBytes;
        }

        if (total > cfg.MaxTotalUploadBytes)
        {
            return Refuse(ShareRefusal.BadRequest("Total upload size exceeds limit."));
        }

        // The queued job builds the archive; refuse now rather than fail the job later (the job reserves the space).
        try
        {
            scratchSpace.EnsureCanAdmit(scratchSpace.ArchiveDemand(total, passwordProtected: false));
        }
        catch (UploadLimitException ex)
        {
            return Refuse(ShareRefusal.From(ex));
        }

        // Fast path for the daily budget of received shares (counted per owner account, so rotating the code does not
        // reset it); the job re-checks it under a per-owner lock before the share is committed.
        var nowUtc = DateTime.UtcNow;
        var usage = await manager.GetReceivedShareUsageAsync(ShareOwner.For(user.Id, user.Email), nowUtc.AddHours(-24), ct);
        var quotaError = PublicUploadPolicy.CheckDailyQuota(usage.Count, usage.Bytes, total, cfg.PublicUploads);
        if (quotaError is not null)
        {
            return Refuse(ShareRefusal.Text(StatusCodes.Status429TooManyRequests, quotaError));
        }

        var shareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
        var tokenOverride = request.ShareTokenOverride?.Trim();
        if (tokenOverride is not null && ShareTokens.IsValid(tokenOverride))
        {
            shareToken = tokenOverride;
        }

        // Received shares follow the owner's default expiry; "indefinite" only when the owner chose it explicitly.
        var ownerExpiryMode = await authService.GetDefaultExpiryModeAsync(user.Id, ct);
        var expiry = PublicUploadPolicy.ResolveExpiry(ownerExpiryMode, cfg.PublicUploads.DefaultExpiryDays, nowUtc);

        var notifyMode = await authService.GetDefaultNotifyModeAsync(user.Id, ct);
        if (notifyMode is not ("none" or "once" or "every_time"))
        {
            notifyMode = "once";
        }

        return PreparedShare.Ok(new QueuedShareCreationJob.Payload(
            UploaderEmail: user.Email,
            DraftShareId: draftShareId,
            ShareToken: shareToken,
            Message: null,
            SenderName: senderName,
            SenderEmail: senderEmail,
            SenderMessage: string.IsNullOrWhiteSpace(senderMessage) ? null : senderMessage,
            DownloadPassword: null,
            ShowPreviews: true,
            ZipFileName: null,
            NotifyMode: notifyMode,
            ExpiryMode: expiry.Mode,
            ExpiresAtUtc: expiry.ExpiresAtUtc,
            TemplateMode: "per_upload",
            TemplateTitle: $"by {senderName} ({senderEmail})",
            TemplateH1: null,
            TemplateDescription: string.IsNullOrWhiteSpace(senderMessage) ? null : senderMessage,
            TemplateBackgroundColorHex: null,
            TemplateContainerPosition: null,
            TemplateBackgroundUploadId: null,
            UploadedFileIds: uploadedFileIds,
            OwnerUserId: user.Id));
    }

    /// <summary>
    /// Sealing stops further staging into the draft and makes a second submission of it a 409; a failed enqueue
    /// unseals it again and reports 503 so the sender can retry. Null when queued.
    /// </summary>
    public static async Task<ShareRefusal?> SealAndQueueAsync(
        ShareManager manager, QueuedShareCreationJob queuedShareCreationJob, QueuedShareCreationJob.Payload payload, CancellationToken ct)
    {
        try
        {
            return await manager.SealDraftForSubmissionAsync(
                payload.OwnerUserId!.Value, payload.DraftShareId, () => { queuedShareCreationJob.Queue(payload); return Task.CompletedTask; }, ct)
                ? null
                : ShareRefusal.Text(StatusCodes.Status409Conflict, "This upload was already submitted.");
        }
        catch (UploadLimitException ex)
        {
            return ShareRefusal.From(ex);
        }
    }

    private static PreparedShare Refuse(ShareRefusal refusal) => PreparedShare.Refuse(refusal);
}
