using System.Globalization;
using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;

namespace Agora.Web.Services;

/// <summary>
/// The share form's fields, raw as submitted (the service trims and validates them). A caller that is not the
/// browser form (an agent) fills the same fields; <see cref="ExpiresAt"/> is only for such callers.
/// </summary>
public sealed record OwnerShareRequest(
    string DraftShareId,
    string ShareToken = "",
    /// <summary>Files sent inline with the request; refused, since files are staged first.</summary>
    int InlineFileCount = 0,
    IEnumerable<string?>? UploadedFileIds = null,
    string ExpiryMode = "",
    /// <summary>Browser "date" mode: a local date and time without an offset, read in the server's time zone.</summary>
    string ExpiresAtUtc = "",
    /// <summary>Agent callers: an RFC 3339 timestamp with an offset, converted to UTC; implies "date" mode.</summary>
    string ExpiresAt = "",
    string NotifyMode = "",
    string DownloadPassword = "",
    string ShowPreviews = "",
    string Message = "",
    string ZipFileName = "",
    string TemplateMode = "",
    string TemplateBackgroundUploadId = "",
    string TemplateTitle = "",
    string TemplateH1 = "",
    string TemplateDescription = "",
    string TemplateBackgroundColorHex = "",
    string TemplateContainerPosition = "");

/// <summary>
/// Validation and payload building of an owner's share submission, shared by the browser route and agent callers.
/// <see cref="PrepareAsync"/> refuses or returns the payload; the caller may adjust it with <c>payload with { ... }</c>
/// and then calls <see cref="ClaimAndSealAsync"/>.
/// </summary>
public static class OwnerShareSubmission
{
    private static readonly string[] Rfc3339Formats =
    [
        "yyyy-MM-dd'T'HH:mm:ssK",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"
    ];

    public static async Task<PreparedShare> PrepareAsync(
        ShareManager manager,
        AuthService authService,
        ScratchSpaceMonitor scratchSpace,
        ShareCreationStatusStore creationStatus,
        AgoraOptions cfg,
        ShareOwner owner,
        OwnerShareRequest request,
        CancellationToken ct,
        DateTime? nowUtc = null)
    {
        var draftShareId = request.DraftShareId.Trim();
        if (string.IsNullOrWhiteSpace(draftShareId))
        {
            return Refuse(ShareRefusal.BadRequest("draftShareId is required"));
        }

        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Refuse(ShareRefusal.BadRequest(ex.Message));
        }
        catch (UploadLimitException ex)
        {
            return Refuse(ShareRefusal.From(ex));
        }

        var shareToken = request.ShareToken.Trim();
        if (string.IsNullOrWhiteSpace(shareToken))
        {
            shareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
        }

        // Refused as plain text, not a redirect: the page keeps the typed token, and no URL can preset a share's token.
        var shareTokenRefusal = await ShareSubmission.RefuseRequestedTokenAsync(manager, creationStatus, shareToken, owner.UserId, draftShareId, ct);
        if (shareTokenRefusal is not null)
        {
            return Refuse(ShareRefusal.Text(StatusCodes.Status400BadRequest, shareTokenRefusal));
        }

        if (request.InlineFileCount > 0)
        {
            return Refuse(ShareRefusal.BadRequest("Please wait for file uploads to finish before creating the share."));
        }

        var uploadedFileIds = (request.UploadedFileIds ?? [])
            .Select(x => x?.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToArray();

        IReadOnlyList<ShareManager.StagedUploadFile> stagedUploads;
        try
        {
            stagedUploads = await manager.ResolveStagedUploadsAsync(owner.UserId, uploadedFileIds, draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Refuse(ShareRefusal.BadRequest(ex.Message));
        }

        if (stagedUploads.Count == 0)
        {
            return Refuse(ShareRefusal.BadRequest("At least one file is required"));
        }

        if (stagedUploads.Count > cfg.MaxFilesPerShare)
        {
            return Refuse(ShareRefusal.BadRequest($"Too many files. Max {cfg.MaxFilesPerShare}"));
        }

        long total = 0;
        foreach (var staged in stagedUploads)
        {
            if (staged.OriginalSizeBytes > cfg.MaxFileSizeBytes)
            {
                return Refuse(ShareRefusal.BadRequest($"File '{staged.OriginalFileName}' exceeds max size"));
            }

            total += staged.OriginalSizeBytes;
        }

        if (total > cfg.MaxTotalUploadBytes)
        {
            return Refuse(ShareRefusal.BadRequest("Total upload size exceeds limit"));
        }

        var now = nowUtc ?? DateTime.UtcNow;
        var expiry = await ResolveExpiryAsync(authService, owner.UserId, request, now, ct);
        if (expiry.Refusal is not null)
        {
            return Refuse(expiry.Refusal);
        }

        var notifyModeRaw = request.NotifyMode.Trim().ToLowerInvariant();
        var notifyMode = notifyModeRaw == "account_default"
            ? await authService.GetDefaultNotifyModeAsync(owner.UserId, ct)
            : notifyModeRaw;
        if (notifyMode is not ("none" or "once" or "every_time"))
        {
            return Refuse(ShareRefusal.BadRequest("notifyMode must be account_default|none|once|every_time"));
        }

        if (!TryNormalizeOptionalSharePassword(request.DownloadPassword, out var downloadPassword))
        {
            return Refuse(ShareRefusal.BadRequest("downloadPassword must be at least 8 characters when provided"));
        }

        var showPreviews = IsTruthy(request.ShowPreviews);
        var perUpload = string.Equals(request.TemplateMode, "per_upload", StringComparison.OrdinalIgnoreCase);

        var templateBackgroundUploadId = request.TemplateBackgroundUploadId.Trim();
        long templateBackgroundBytes = 0;
        if (!string.IsNullOrWhiteSpace(templateBackgroundUploadId))
        {
            try
            {
                var stagedBackground = await manager.ResolveStagedUploadsAsync(
                    owner.UserId,
                    [templateBackgroundUploadId],
                    draftShareId,
                    ct,
                    ShareManager.UploadPurposeTemplateBackground);
                templateBackgroundBytes = stagedBackground.Sum(x => x.OriginalSizeBytes);
            }
            catch (InvalidOperationException ex)
            {
                return Refuse(ShareRefusal.BadRequest(ex.Message));
            }
        }

        // The queued job builds the archive; refuse now rather than fail the job later (the job reserves the space).
        try
        {
            scratchSpace.EnsureCanAdmit(scratchSpace.ArchiveDemand(total, passwordProtected: downloadPassword is not null, backgroundBytes: templateBackgroundBytes));
        }
        catch (UploadLimitException ex)
        {
            return Refuse(ShareRefusal.From(ex));
        }

        return PreparedShare.Ok(new QueuedShareCreationJob.Payload(
            UploaderEmail: owner.Email,
            DraftShareId: draftShareId,
            ShareToken: shareToken,
            Message: request.Message,
            SenderName: null,
            SenderEmail: null,
            SenderMessage: null,
            DownloadPassword: downloadPassword,
            ShowPreviews: showPreviews,
            ZipFileName: request.ZipFileName,
            NotifyMode: notifyMode,
            ExpiryMode: expiry.Mode!,
            ExpiresAtUtc: expiry.ExpiresAtUtc,
            TemplateMode: perUpload ? "per_upload" : "account_default",
            TemplateTitle: request.TemplateTitle,
            TemplateH1: request.TemplateH1,
            TemplateDescription: request.TemplateDescription,
            TemplateBackgroundColorHex: NormalizeHexColor(request.TemplateBackgroundColorHex),
            TemplateContainerPosition: ShareManager.NormalizeContainerPosition(request.TemplateContainerPosition),
            TemplateBackgroundUploadId: templateBackgroundUploadId,
            UploadedFileIds: uploadedFileIds,
            OwnerUserId: owner.UserId));
    }

    /// <summary>
    /// The link is claimed just before sealing (after every refusal in <see cref="PrepareAsync"/>) so only a
    /// submission that is queued holds it. Sealing stops further staging into the draft and makes a second submission
    /// of it a 409; a failed enqueue unseals it again and reports 503 so the caller can retry. Null when queued.
    /// </summary>
    public static async Task<ShareRefusal?> ClaimAndSealAsync(
        ShareManager manager, QueuedShareCreationJob queuedShareCreationJob, QueuedShareCreationJob.Payload payload, CancellationToken ct)
    {
        try
        {
            var submission = await ShareSubmission.ClaimAndSealAsync(
                manager, payload.ShareToken, payload.OwnerUserId!.Value, payload.DraftShareId,
                () => { queuedShareCreationJob.Queue(payload); return Task.CompletedTask; }, ct);
            if (submission.Refused)
            {
                return ShareRefusal.Text(StatusCodes.Status400BadRequest, submission.Text!);
            }

            return submission.Sealed ? null : ShareRefusal.Text(StatusCodes.Status409Conflict, "This share was already submitted.");
        }
        catch (UploadLimitException ex)
        {
            return ShareRefusal.From(ex);
        }
    }

    private static async Task<(string? Mode, DateTime? ExpiresAtUtc, ShareRefusal? Refusal)> ResolveExpiryAsync(
        AuthService authService, Guid ownerUserId, OwnerShareRequest request, DateTime nowUtc, CancellationToken ct)
    {
        var mode = request.ExpiryMode.Trim().ToLowerInvariant();
        var absolute = request.ExpiresAt.Trim();
        if (absolute.Length > 0)
        {
            // An absolute timestamp is an explicit date; it cannot be combined with a relative mode.
            if (mode.Length > 0 && mode != "date")
            {
                return (null, null, ShareRefusal.BadRequest("expiresAt can only be combined with expiryMode date"));
            }

            if (!DateTimeOffset.TryParseExact(absolute, Rfc3339Formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedOffset) ||
                !HasOffset(absolute))
            {
                return (null, null, ShareRefusal.BadRequest("expiresAt must be an RFC 3339 timestamp with an offset, such as 2026-12-31T18:00:00Z"));
            }

            var utc = parsedOffset.UtcDateTime;
            return utc <= nowUtc
                ? (null, null, ShareRefusal.BadRequest("expiresAt must be in the future"))
                : ("date", utc, null);
        }

        if (mode == "account_default")
        {
            mode = await authService.GetDefaultExpiryModeAsync(ownerUserId, ct);
        }

        DateTime? expiresAtUtc = mode switch
        {
            "1_hour" => nowUtc.AddHours(1),
            "24_hours" => nowUtc.AddHours(24),
            "7_days" => nowUtc.AddDays(7),
            "30_days" => nowUtc.AddDays(30),
            "1_year" => nowUtc.AddYears(1),
            _ => null
        };

        if (mode == "date")
        {
            if (!DateTime.TryParse(request.ExpiresAtUtc, out var parsed))
            {
                return (null, null, ShareRefusal.BadRequest("expiresAtUtc is required for date mode"));
            }

            expiresAtUtc = DateTime.SpecifyKind(parsed, DateTimeKind.Local).ToUniversalTime();
            if (expiresAtUtc <= nowUtc)
            {
                return (null, null, ShareRefusal.BadRequest("expiresAtUtc must be in the future"));
            }
        }
        else if (mode is not ("1_hour" or "24_hours" or "7_days" or "30_days" or "1_year" or "indefinite"))
        {
            return (null, null, ShareRefusal.BadRequest("expiryMode must be 1_hour|24_hours|7_days|30_days|1_year|date|indefinite"));
        }

        return (mode, expiresAtUtc, null);
    }

    // The format strings accept an offset-less value too (K matches nothing); RFC 3339 requires Z or +hh:mm.
    private static bool HasOffset(string value) =>
        value.EndsWith('Z') || value.EndsWith('z') ||
        (value.Length > 6 && value[^6] is ('+' or '-') && value[^3] == ':');

    public static bool IsTruthy(string? raw)
    {
        var value = (raw ?? string.Empty).Trim().ToLowerInvariant();
        return value is "1" or "true" or "on" or "yes";
    }

    /// <summary>Blank gives null (no password); otherwise the trimmed value must be 8 to 256 characters.</summary>
    public static bool TryNormalizeOptionalSharePassword(string? raw, out string? password)
    {
        password = string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();
        if (password is null)
        {
            return true;
        }

        return password.Length >= 8 && password.Length <= 256;
    }

    public static string? NormalizeHexColor(string? value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            return null;
        }

        if (trimmed[0] != '#')
        {
            trimmed = "#" + trimmed;
        }

        if (trimmed.Length != 7)
        {
            return null;
        }

        for (var i = 1; i < trimmed.Length; i++)
        {
            var c = trimmed[i];
            var isHex = (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
            if (!isHex)
            {
                return null;
            }
        }

        return trimmed.ToLowerInvariant();
    }

    private static PreparedShare Refuse(ShareRefusal refusal) => PreparedShare.Refuse(refusal);
}
