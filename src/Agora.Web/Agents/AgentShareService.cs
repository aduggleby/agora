using System.Text.Json.Serialization;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Microsoft.Extensions.Options;

namespace Agora.Web.Agents;

public sealed record AgentFileView(string Id, string Name, long SizeBytes);

public sealed record AgentSender(string? Name, string? Email, string? Message);

/// <summary>
/// A share as the agent API reports it. Only the first five fields are present while a share is still being created;
/// the password appears only in the create response. Received items carry the untrusted label and notice.
/// </summary>
public sealed record AgentShareView(
    string Token,
    string Url,
    bool Ready,
    string State,
    string? Error,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Password = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? PasswordProtected = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Title = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ArchiveName = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<AgentFileView>? Files = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTime? CreatedAtUtc = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTime? ExpiresAtUtc = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? DownloadCount = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Received = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? SentByAgent = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AgentSender? Sender = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Untrusted = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Notice = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Kind = null);

public sealed record UploadUrlInfo(string DraftId, string UploadUrl, DateTime ExpiresAtUtc);

public sealed record DownloadUrlInfo(string DownloadUrl, DateTime ExpiresAtUtc, string FileName, long SizeBytes);

/// <summary>An opened stored original; <see cref="Received"/> files get the untrusted marking on their response.</summary>
public sealed record ShareFileContent(ObjectStream Content, string FileName, bool Received);

public sealed record PageOptions(
    string? Title = null,
    string? H1 = null,
    string? Description = null,
    string? BackgroundColorHex = null,
    string? ContainerPosition = null,
    string? BackgroundFileId = null);

/// <summary>
/// Create-share input. Give <see cref="DraftId"/> (files staged earlier; <see cref="FileIds"/> defaults to all of
/// them) or <see cref="Files"/> (inline, staged into a new draft), not both. Left-out options take the owner's
/// share defaults.
/// </summary>
public sealed record CreateShareRequest(
    string? DraftId = null,
    IReadOnlyList<InlineFile>? Files = null,
    IReadOnlyList<string>? FileIds = null,
    string? ShareCode = null,
    string? Message = null,
    string? ZipFileName = null,
    string? Expiry = null,
    string? ExpiresAt = null,
    string? Notify = null,
    string? DownloadPassword = null,
    bool? ShowPreviews = null,
    PageOptions? Page = null,
    int? WaitSeconds = null);

/// <summary>
/// What an owner's agent can do: stage files (inline or through one-time URLs), create shares with any option the
/// new-share page has, list, read and delete shares within its access level, and, at level "all", download files.
/// Shared by the HTTP routes and the MCP tools; every refusal is an <see cref="AgentResult{T}"/>.
/// </summary>
public sealed class AgentShareService(
    ShareManager manager,
    AuthService authService,
    ScratchSpaceMonitor scratchSpace,
    ShareCreationStatusStore creationStatus,
    QueuedShareCreationJob queuedShareCreationJob,
    UploadConcurrency concurrency,
    AgentTicketStore tickets,
    IObjectStore objectStore,
    IOptions<AgoraOptions> options)
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    private AgoraOptions Cfg => options.Value;

    // ---- staging ----

    /// <summary>Stages one inline file. Without a draft id a new draft is opened (and removed again when the file is refused).</summary>
    public async Task<AgentResult<StagedFileInfo>> UploadInlineAsync(
        AgentCaller caller, string? draftId, InlineFile file, string? purpose, CancellationToken ct)
    {
        if (!AgentStaging.IsValidPurpose(purpose))
        {
            return AgentResult<StagedFileInfo>.BadRequest("purpose must be file or background.");
        }

        var staged = await StageInlineAsync(caller, draftId, [file], AgentStaging.PurposeToStorage(purpose), ct);
        return staged.IsOk ? AgentResult<StagedFileInfo>.Ok(staged.Value![0], StatusCodes.Status201Created) : staged.Refusal<StagedFileInfo>();
    }

    private async Task<AgentResult<IReadOnlyList<StagedFileInfo>>> StageInlineAsync(
        AgentCaller caller, string? draftId, IReadOnlyList<InlineFile> files, string purpose, CancellationToken ct)
    {
        var decoded = AgentStaging.DecodeInline(files);
        if (!decoded.IsOk)
        {
            return decoded.Refusal<IReadOnlyList<StagedFileInfo>>();
        }

        var opened = await OpenDraftAsync(caller, draftId, ct);
        if (!opened.IsOk)
        {
            return opened.Refusal<IReadOnlyList<StagedFileInfo>>();
        }

        var draft = opened.Value!;
        var created = string.IsNullOrWhiteSpace(draftId);
        var ok = false;
        try
        {
            using var lease = concurrency.TryAcquire(UploadConcurrency.DraftKey(draft));
            if (lease is null)
            {
                return AgentResult<IReadOnlyList<StagedFileInfo>>.Refuse(StatusCodes.Status429TooManyRequests, UploadConcurrency.RefusalMessage);
            }

            var result = new List<StagedFileInfo>();
            foreach (var (name, bytes) in decoded.Value!)
            {
                // The budget pre-check of the browser routes, before the bytes are copied.
                if (await AgentStaging.CheckSizeAsync(manager, Cfg, draft, purpose, bytes.Length, ct) is { } refused)
                {
                    return refused.Refusal<IReadOnlyList<StagedFileInfo>>();
                }

                await using var stream = new MemoryStream(bytes, writable: false);
                var staged = await AgentStaging.StageAsync(manager, Cfg, caller.Owner.UserId, draft, name, stream, purpose, ct);
                if (!staged.IsOk)
                {
                    return staged.Refusal<IReadOnlyList<StagedFileInfo>>();
                }

                result.Add(staged.Value!);
            }

            ok = true;
            return AgentResult<IReadOnlyList<StagedFileInfo>>.Ok(result);
        }
        finally
        {
            if (!ok && created)
            {
                await DiscardDraftAsync(caller.Owner.UserId, draft);
            }
        }
    }

    /// <summary>Issues a one-time URL the agent PUTs one file to, after the same admission as a browser stage.</summary>
    public async Task<AgentResult<UploadUrlInfo>> IssueUploadUrlAsync(
        AgentCaller caller, string baseUrl, string? draftId, string? fileName, long sizeBytes, string? purpose, CancellationToken ct)
    {
        if (!AgentStaging.IsValidPurpose(purpose))
        {
            return AgentResult<UploadUrlInfo>.BadRequest("purpose must be file or background.");
        }

        var name = AgentStaging.CheckFileName(fileName);
        if (!name.IsOk)
        {
            return name.Refusal<UploadUrlInfo>();
        }

        if (sizeBytes <= 0)
        {
            return AgentResult<UploadUrlInfo>.BadRequest("sizeBytes must be greater than 0.");
        }

        var storagePurpose = AgentStaging.PurposeToStorage(purpose);
        var opened = await OpenDraftAsync(caller, draftId, ct);
        if (!opened.IsOk)
        {
            return opened.Refusal<UploadUrlInfo>();
        }

        var draft = opened.Value!;
        var created = string.IsNullOrWhiteSpace(draftId);
        var refusal = await AgentStaging.CheckSizeAsync(manager, Cfg, draft, storagePurpose, sizeBytes, ct);
        if (refusal is not null)
        {
            if (created)
            {
                await DiscardDraftAsync(caller.Owner.UserId, draft);
            }

            return refusal.Refusal<UploadUrlInfo>();
        }

        var expires = tickets.UtcNow + AgentLimits.TicketLifetime;
        var ticket = tickets.Issue(new AgentTicketStore.Ticket(
            AgentTicketStore.KindUpload,
            caller.Owner.UserId,
            expires,
            DraftId: draft,
            Purpose: storagePurpose == ShareManager.UploadPurposeTemplateBackground ? AgentTicketStore.PurposeBackground : AgentTicketStore.PurposeFile,
            FileName: name.Value,
            SizeBytes: sizeBytes,
            TokenId: caller.TokenId));
        return AgentResult<UploadUrlInfo>.Ok(new UploadUrlInfo(draft, $"{baseUrl}/api/v1/upload-urls/{ticket}", expires), StatusCodes.Status201Created);
    }

    private async Task<AgentResult<string>> OpenDraftAsync(AgentCaller caller, string? draftId, CancellationToken ct)
    {
        try
        {
            return AgentResult<string>.Ok(await manager.EnsureDraftShareAsync(caller.Owner.UserId, string.IsNullOrWhiteSpace(draftId) ? null : draftId.Trim(), ct));
        }
        catch (InvalidOperationException ex)
        {
            return AgentResult<string>.BadRequest(ex.Message);
        }
        catch (UploadLimitException ex)
        {
            return AgentResult<string>.From(ex);
        }
    }

    private async Task DiscardDraftAsync(Guid ownerUserId, string draftId)
    {
        try
        {
            await manager.FinalizeDraftAsync(ownerUserId, draftId, CancellationToken.None);
        }
        catch (Exception)
        {
            // The zombie sweep removes what is left.
        }
    }

    // ---- shares ----

    public async Task<AgentResult<AgentShareView>> CreateShareAsync(
        AgentCaller caller, string baseUrl, CreateShareRequest request, CancellationToken ct)
    {
        var hasDraft = !string.IsNullOrWhiteSpace(request.DraftId);
        var hasFiles = request.Files is { Count: > 0 };
        if (hasDraft == hasFiles)
        {
            return AgentResult<AgentShareView>.BadRequest(hasDraft ? "Give draftId or files, not both." : "draftId or files is required.");
        }

        var fileIds = request.FileIds?.ToArray();
        var draftId = request.DraftId;
        var createdDraft = false;
        if (hasFiles)
        {
            var staged = await StageInlineAsync(caller, null, request.Files!, ShareManager.UploadPurposeShareFile, ct);
            if (!staged.IsOk)
            {
                return staged.Refusal<AgentShareView>();
            }

            draftId = staged.Value![0].DraftId;
            fileIds = staged.Value.Select(x => x.FileId).ToArray();
            createdDraft = true;
        }
        else if (fileIds is null or { Length: 0 })
        {
            try
            {
                var draft = await manager.EnsureDraftShareAsync(caller.Owner.UserId, draftId!.Trim(), ct);
                fileIds = (await manager.ListStagedUploadsForDraftAsync(caller.Owner.UserId, draft, ct)).Select(x => x.UploadId).ToArray();
            }
            catch (InvalidOperationException ex)
            {
                return AgentResult<AgentShareView>.BadRequest(ex.Message);
            }
            catch (UploadLimitException ex)
            {
                return AgentResult<AgentShareView>.From(ex);
            }
        }

        var page = request.Page;
        var form = new OwnerShareRequest(
            DraftShareId: draftId!,
            ShareToken: request.ShareCode ?? string.Empty,
            UploadedFileIds: fileIds,
            ExpiryMode: request.Expiry ?? (string.IsNullOrWhiteSpace(request.ExpiresAt) ? "account_default" : string.Empty),
            ExpiresAt: request.ExpiresAt ?? string.Empty,
            NotifyMode: request.Notify ?? "account_default",
            DownloadPassword: request.DownloadPassword ?? string.Empty,
            ShowPreviews: request.ShowPreviews == true ? "true" : string.Empty,
            Message: request.Message ?? string.Empty,
            ZipFileName: request.ZipFileName ?? string.Empty,
            TemplateMode: page is null ? "account_default" : "per_upload",
            TemplateBackgroundUploadId: page?.BackgroundFileId ?? string.Empty,
            TemplateTitle: page?.Title ?? string.Empty,
            TemplateH1: page?.H1 ?? string.Empty,
            TemplateDescription: page?.Description ?? string.Empty,
            TemplateBackgroundColorHex: page?.BackgroundColorHex ?? string.Empty,
            TemplateContainerPosition: page?.ContainerPosition ?? string.Empty);

        var prepared = await OwnerShareSubmission.PrepareAsync(manager, authService, scratchSpace, creationStatus, Cfg, caller.Owner, form, ct);
        if (prepared.Refusal is not null)
        {
            if (createdDraft)
            {
                await DiscardDraftAsync(caller.Owner.UserId, draftId!);
            }

            return AgentResult<AgentShareView>.Refuse(prepared.Refusal.Status, prepared.Refusal.Message);
        }

        var payload = prepared.Payload! with { CreatedByApiTokenId = caller.TokenId };
        var sealRefusal = await OwnerShareSubmission.ClaimAndSealAsync(manager, queuedShareCreationJob, payload, ct);
        if (sealRefusal is not null)
        {
            return AgentResult<AgentShareView>.Refuse(sealRefusal.Status, sealRefusal.Message);
        }

        var wait = TimeSpan.FromSeconds(Math.Clamp(request.WaitSeconds ?? AgentLimits.DefaultWaitSeconds, 0, AgentLimits.MaxWaitSeconds));
        var deadline = DateTime.UtcNow + wait;
        AgentShareView view;
        while (true)
        {
            view = await ReadViewAsync(caller, baseUrl, payload.ShareToken, ct) ?? QueuedView(baseUrl, payload.ShareToken);
            if (view.Ready || view.State == "failed" || DateTime.UtcNow >= deadline)
            {
                break;
            }

            await Task.Delay(PollInterval, ct);
        }

        // The password is shown here and never again: later reads only say it is set.
        return AgentResult<AgentShareView>.Ok(view with { Password = payload.DownloadPassword }, StatusCodes.Status201Created);
    }

    public async Task<AgentResult<AgentShareView>> GetShareAsync(AgentCaller caller, string baseUrl, string token, CancellationToken ct)
    {
        var view = ShareTokens.IsValid(token) ? await ReadViewAsync(caller, baseUrl, token, ct) : null;
        return view is null ? AgentResult<AgentShareView>.NotFound(NoSuchShare) : AgentResult<AgentShareView>.Ok(view);
    }

    public async Task<AgentResult<IReadOnlyList<AgentShareView>>> ListSharesAsync(AgentCaller caller, string baseUrl, int? limit, CancellationToken ct)
    {
        var take = Math.Clamp(limit ?? 25, 1, AgentLimits.MaxListShares);
        var shares = await manager.ListAgentSharesAsync(caller.Owner, caller.ScopeTokenId, take, ct);
        return AgentResult<IReadOnlyList<AgentShareView>>.Ok(shares.Select(x => ToView(baseUrl, x)).ToList());
    }

    /// <summary>Deletes a share in scope (level own: only this token's). 404 for everything else, so existence does not leak.</summary>
    public async Task<AgentResult<bool>> DeleteShareAsync(AgentCaller caller, string token, CancellationToken ct)
    {
        return ShareTokens.IsValid(token) && await manager.DeleteShareForAgentAsync(caller.Owner, caller.ScopeTokenId, token, ct)
            ? AgentResult<bool>.Ok(true, StatusCodes.Status204NoContent)
            : AgentResult<bool>.NotFound(NoSuchShare);
    }

    /// <summary>The files of a share with their ids and the received labeling; level "all" only.</summary>
    public async Task<AgentResult<AgentShareView>> ListFilesAsync(AgentCaller caller, string baseUrl, string token, CancellationToken ct)
    {
        return RequireAll(caller) is { } refusal ? refusal.Refusal<AgentShareView>() : await GetShareAsync(caller, baseUrl, token, ct);
    }

    public Task<AgentResult<ShareFileContent>> OpenFileAsync(AgentCaller caller, string token, string fileId, CancellationToken ct) =>
        RequireAll(caller) is { } refusal ? Task.FromResult(refusal.Refusal<ShareFileContent>()) : OpenFileAsync(caller.Owner.UserId, token, fileId, ct);

    /// <summary>Opens a stored original of one of the owner's shares (deleted shares are gone). Not a download event.</summary>
    public async Task<AgentResult<ShareFileContent>> OpenFileAsync(Guid ownerUserId, string token, string fileId, CancellationToken ct)
    {
        var share = ShareTokens.IsValid(token) ? await manager.FindByTokenAsync(token, ct) : null;
        var file = share is not null && share.OwnerUserId == ownerUserId && !ShareManager.IsDeleted(share) &&
                   string.Equals(share.ShareToken, token, StringComparison.Ordinal) && Guid.TryParse(fileId, out var id)
            ? share.Files.SingleOrDefault(x => x.Id == id)
            : null;
        if (file is null)
        {
            return AgentResult<ShareFileContent>.NotFound("No such file.");
        }

        var stored = ObjectKey.TryNormalize(file.StoredRelativePath, out var key) ? await objectStore.OpenReadAsync(key, ct) : null;
        return stored is null
            ? AgentResult<ShareFileContent>.Refuse(StatusCodes.Status410Gone, "The file is no longer stored.")
            : AgentResult<ShareFileContent>.Ok(new ShareFileContent(stored, file.OriginalFilename, share!.SenderEmail is not null));
    }

    /// <summary>A one-time download URL for a file (MCP uses it for files over the inline limit); level "all" only.</summary>
    public async Task<AgentResult<DownloadUrlInfo>> IssueDownloadUrlAsync(AgentCaller caller, string baseUrl, string token, string fileId, CancellationToken ct)
    {
        if (RequireAll(caller) is { } refusal)
        {
            return refusal.Refusal<DownloadUrlInfo>();
        }

        var share = ShareTokens.IsValid(token) ? await manager.FindByTokenAsync(token, ct) : null;
        var file = share is not null && share.OwnerUserId == caller.Owner.UserId && !ShareManager.IsDeleted(share) &&
                   string.Equals(share.ShareToken, token, StringComparison.Ordinal) && Guid.TryParse(fileId, out var id)
            ? share.Files.SingleOrDefault(x => x.Id == id)
            : null;
        if (file is null)
        {
            return AgentResult<DownloadUrlInfo>.NotFound("No such file.");
        }

        var expires = tickets.UtcNow + AgentLimits.TicketLifetime;
        var ticket = tickets.Issue(new AgentTicketStore.Ticket(
            AgentTicketStore.KindDownload, caller.Owner.UserId, expires, ShareToken: token, FileId: file.Id, TokenId: caller.TokenId));
        return AgentResult<DownloadUrlInfo>.Ok(new DownloadUrlInfo($"{baseUrl}/api/v1/download-urls/{ticket}", expires, file.OriginalFilename, file.OriginalSizeBytes));
    }

    // ---- views ----

    private const string NoSuchShare = "No such share.";

    private static AgentResult<bool>? RequireAll(AgentCaller caller) =>
        caller.CanSeeAll ? null : AgentResult<bool>.Refuse(StatusCodes.Status403Forbidden, "Downloads need All my shares access.");

    private static AgentShareView QueuedView(string baseUrl, string token) => new(token, ShareUrl(baseUrl, token), false, "queued", null);

    private static string ShareUrl(string baseUrl, string token) => $"{baseUrl}/s/{Uri.EscapeDataString(token)}";

    /// <summary>
    /// The share once created, else its creation status. A finished creation whose share is not visible to the caller
    /// (deleted, or out of its scope) is "not found", so a status file cannot reveal a share the token may not see.
    /// </summary>
    private async Task<AgentShareView?> ReadViewAsync(AgentCaller caller, string baseUrl, string token, CancellationToken ct)
    {
        var summary = await manager.FindAgentShareAsync(caller.Owner, caller.ScopeTokenId, token, ct);
        if (summary is not null)
        {
            return ToView(baseUrl, summary);
        }

        var status = creationStatus.Read(token);
        if (status is null || status.OwnerUserId != caller.Owner.UserId || ShareCreationStatusView.IsCompleted(status.State))
        {
            return null;
        }

        return new AgentShareView(token, ShareUrl(baseUrl, token), false, status.State, status.Error);
    }

    private static AgentShareView ToView(string baseUrl, ShareManager.AgentShareSummary x) => new(
        x.ShareToken,
        ShareUrl(baseUrl, x.ShareToken),
        true,
        "completed",
        null,
        PasswordProtected: x.PasswordProtected,
        Title: x.Title,
        ArchiveName: x.ZipDisplayName,
        Files: x.Files.Select(f => new AgentFileView(f.Id.ToString(), f.Name, f.SizeBytes)).ToList(),
        CreatedAtUtc: x.CreatedAtUtc,
        ExpiresAtUtc: x.ExpiresAtUtc,
        DownloadCount: x.DownloadCount,
        Received: x.Received,
        SentByAgent: x.SentByAgent,
        Sender: x.Received ? new AgentSender(x.SenderName, x.SenderEmail, x.SenderMessage) : null,
        Untrusted: x.Received ? true : null,
        Notice: x.Received ? AgentLimits.UntrustedNotice : null,
        Kind: x.IsDirectLink ? "direct_link" : "share");
}
