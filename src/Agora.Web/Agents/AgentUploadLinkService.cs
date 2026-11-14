using System.Security.Cryptography;
using System.Text;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Microsoft.Extensions.Options;

namespace Agora.Web.Agents;

/// <summary>What an anonymous agent may learn about an upload link whose owner accepts agent uploads.</summary>
public sealed record UploadLinkInfo(string RecipientName, bool AcceptsAgentUploads, object Limits);

/// <summary>
/// A send through an upload link. Give <see cref="Files"/> (inline, staged into a new or the given draft) and/or
/// <see cref="DraftId"/> of a draft this interface issued; <see cref="FileIds"/> defaults to every staged file.
/// </summary>
public sealed record SendFilesRequest(
    string? DraftId,
    IReadOnlyList<InlineFile>? Files,
    IReadOnlyList<string>? FileIds,
    string? SenderName,
    string? SenderEmail,
    string? Message);

public sealed record SendFilesResult(string State);

/// <summary>
/// The anonymous agent interface of an upload link (HTTP routes and MCP tools). On every call the code is resolved
/// first (404), then the owner's switch (403), then everything else; a regenerated code stops working at once, with
/// its tickets. Drafts are opened server-side only: the id is minted here and remembered per upload code, and later
/// calls accept just those ids, never one the client chose. Limits are the browser's: open-draft caps, staging
/// budgets, in-flight caps per address and draft, daily quota.
/// </summary>
public sealed class AgentUploadLinkService(
    AuthService authService,
    ShareManager manager,
    ScratchSpaceMonitor scratchSpace,
    QueuedShareCreationJob queuedShareCreationJob,
    UploadConcurrency concurrency,
    AgentTicketStore tickets,
    IOptions<AgoraOptions> options) : IPublicDraftAdmission
{
    private AgoraOptions Cfg => options.Value;

    private string DraftMarkerRoot => Path.Combine(Cfg.StorageRoot, "uploads", "agent-drafts");

    public static string AgentsDisabledMessage(string baseUrl, string code) =>
        $"The owner of this upload link does not accept uploads from AI agents. A person can still send files at {baseUrl}/u/{Uri.EscapeDataString(code)} in a browser.";

    /// <summary>The owner of the code, in the fixed order: unknown code 404, switch off 403.</summary>
    public async Task<AgentResult<UserAccount>> ResolveAsync(string? code, string baseUrl, CancellationToken ct)
    {
        var trimmed = (code ?? string.Empty).Trim();
        var user = string.IsNullOrEmpty(trimmed) ? null : await authService.FindByUploadTokenAsync(trimmed, ct);
        if (user is null)
        {
            return AgentResult<UserAccount>.NotFound("Upload link not found.");
        }

        return user.AllowAgentUploads
            ? AgentResult<UserAccount>.Ok(user)
            : AgentResult<UserAccount>.Refuse(StatusCodes.Status403Forbidden, AgentsDisabledMessage(baseUrl, user.UploadToken));
    }

    public async Task<AgentResult<UploadLinkInfo>> DescribeAsync(string? code, string baseUrl, CancellationToken ct)
    {
        var owner = await ResolveAsync(code, baseUrl, ct);
        if (!owner.IsOk)
        {
            return owner.Refusal<UploadLinkInfo>();
        }

        var name = string.IsNullOrWhiteSpace(owner.Value!.DisplayName) ? "the owner of this upload link" : owner.Value.DisplayName.Trim();
        return AgentResult<UploadLinkInfo>.Ok(new UploadLinkInfo(name, true, AgentLimits.Describe(Cfg)));
    }

    /// <summary>Stages one inline file into a draft of this link (a new one without <paramref name="draftId"/>).</summary>
    public async Task<AgentResult<StagedFileInfo>> UploadInlineAsync(
        string? code, string baseUrl, string clientAddress, string? draftId, InlineFile file, CancellationToken ct)
    {
        var staged = await StageInlineAsync(code, baseUrl, clientAddress, draftId, [file], ct);
        return staged.IsOk
            ? AgentResult<StagedFileInfo>.Ok(staged.Value!.Files[0], StatusCodes.Status201Created)
            : staged.Refusal<StagedFileInfo>();
    }

    /// <summary>Issues a one-time URL for one file after the admission a browser stage gets (draft caps, budgets, file limits).</summary>
    public async Task<AgentResult<UploadUrlInfo>> IssueUploadUrlAsync(
        string? code, string baseUrl, string clientAddress, string? draftId, string? fileName, long sizeBytes, CancellationToken ct)
    {
        var owner = await ResolveAsync(code, baseUrl, ct);
        if (!owner.IsOk)
        {
            return owner.Refusal<UploadUrlInfo>();
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

        var user = owner.Value!;
        var opened = await OpenDraftAsync(user, clientAddress, draftId, scratchBytes: Math.Min(sizeBytes, Cfg.MaxFileSizeBytes), ct);
        if (!opened.IsOk)
        {
            return opened.Refusal<UploadUrlInfo>();
        }

        var (draft, created) = opened.Value;
        if (await AgentStaging.CheckSizeAsync(manager, Cfg, draft, ShareManager.UploadPurposeShareFile, sizeBytes, ct) is { } refusal)
        {
            await DiscardIfCreatedAsync(user, draft, created);
            return refusal.Refusal<UploadUrlInfo>();
        }

        var expires = tickets.UtcNow + AgentLimits.TicketLifetime;
        var ticket = tickets.Issue(new AgentTicketStore.Ticket(
            AgentTicketStore.KindUpload,
            user.Id,
            expires,
            DraftId: draft,
            UploadCode: user.UploadToken,
            Purpose: AgentTicketStore.PurposeFile,
            FileName: name.Value,
            SizeBytes: sizeBytes));
        return AgentResult<UploadUrlInfo>.Ok(new UploadUrlInfo(draft, $"{baseUrl}/api/v1/upload-urls/{ticket}", expires), StatusCodes.Status201Created);
    }

    /// <summary>
    /// Submits a draft (inline files are staged first) as a received share marked as sent through the agent
    /// interface. Queued, not created: there is no share link to give back.
    /// </summary>
    public async Task<AgentResult<SendFilesResult>> SendAsync(
        string? code, string baseUrl, string clientAddress, SendFilesRequest request, CancellationToken ct)
    {
        var owner = await ResolveAsync(code, baseUrl, ct);
        if (!owner.IsOk)
        {
            return owner.Refusal<SendFilesResult>();
        }

        var user = owner.Value!;
        var hasFiles = request.Files is { Count: > 0 };
        var draft = request.DraftId?.Trim();
        var shaped = new PublicShareRequest(
            user.UploadToken,
            string.IsNullOrEmpty(draft) ? "pending" : draft,
            request.SenderName ?? string.Empty,
            request.SenderEmail ?? string.Empty,
            request.Message ?? string.Empty,
            request.FileIds ?? []);
        // Sender fields are checked before anything is staged, so a bad sender leaves no draft behind.
        if (PublicShareSubmission.CheckSender(shaped) is { } senderRefusal)
        {
            return AgentResult<SendFilesResult>.Refuse(senderRefusal.Status, senderRefusal.Message);
        }

        if (!hasFiles && string.IsNullOrEmpty(draft))
        {
            return AgentResult<SendFilesResult>.BadRequest("draftId or files is required.");
        }

        var created = false;
        IReadOnlyList<string> fileIds = request.FileIds ?? [];
        if (hasFiles)
        {
            var staged = await StageInlineAsync(code, baseUrl, clientAddress, draft, request.Files!, ct);
            if (!staged.IsOk)
            {
                return staged.Refusal<SendFilesResult>();
            }

            draft = staged.Value!.DraftId;
            created = staged.Value.Created;
            fileIds = fileIds.Count > 0 ? fileIds : staged.Value.Files.Select(x => x.FileId).ToArray();
        }
        else
        {
            if (!IsIssuedDraft(user.UploadToken, draft))
            {
                return AgentResult<SendFilesResult>.BadRequest(UnknownDraftMessage);
            }

            if (fileIds.Count == 0)
            {
                try
                {
                    var id = await manager.FindPublicUploadDraftAsync(user.Id, draft, ct);
                    fileIds = (await manager.ListStagedUploadsForDraftAsync(user.Id, id, ct)).Select(x => x.UploadId).ToArray();
                }
                catch (InvalidOperationException ex)
                {
                    return AgentResult<SendFilesResult>.BadRequest(ex.Message);
                }
                catch (UploadLimitException ex)
                {
                    return AgentResult<SendFilesResult>.From(ex);
                }
            }
        }

        var prepared = await PublicShareSubmission.PrepareAsync(
            authService, manager, scratchSpace, Cfg,
            shaped with { DraftShareId = draft!, UploadedFileIds = fileIds }, ct);
        if (prepared.Refusal is not null)
        {
            await DiscardIfCreatedAsync(user, draft!, created);
            return AgentResult<SendFilesResult>.Refuse(prepared.Refusal.Status, prepared.Refusal.Message);
        }

        var payload = prepared.Payload! with { SentByAgent = true };
        var sealRefusal = await PublicShareSubmission.SealAndQueueAsync(manager, queuedShareCreationJob, payload, ct);
        if (sealRefusal is not null)
        {
            await DiscardIfCreatedAsync(user, draft!, created);
            return AgentResult<SendFilesResult>.Refuse(sealRefusal.Status, sealRefusal.Message);
        }

        return AgentResult<SendFilesResult>.Ok(new SendFilesResult("queued"), StatusCodes.Status202Accepted);
    }

    /// <summary>
    /// Admission of a public one-time URL at the time it is used: the code still resolves to the ticket's owner
    /// (a regenerated code ends its tickets), the owner still accepts agent uploads, the draft is one this interface
    /// issued and is still open.
    /// </summary>
    public async Task<AgentResult<PublicTicketAdmission>> AdmitAsync(AgentTicketStore.Ticket ticket, HttpContext context, CancellationToken ct)
    {
        const string invalid = "This upload URL is invalid, expired or already used.";
        var user = ticket.UploadCode is { } code ? await authService.FindByUploadTokenAsync(code, ct) : null;
        if (user is null || user.Id != ticket.OwnerUserId || ticket.DraftId is null)
        {
            return AgentResult<PublicTicketAdmission>.NotFound(invalid);
        }

        if (!user.AllowAgentUploads)
        {
            return AgentResult<PublicTicketAdmission>.Refuse(StatusCodes.Status403Forbidden, AgentsDisabledMessage(context.RequestServices.GetRequiredService<PublicBaseUrlResolver>().Resolve(context.Request), user.UploadToken));
        }

        if (!IsIssuedDraft(user.UploadToken, ticket.DraftId))
        {
            return AgentResult<PublicTicketAdmission>.NotFound(invalid);
        }

        try
        {
            var draft = await manager.FindPublicUploadDraftAsync(user.Id, ticket.DraftId, ct);
            TouchDraft(user.UploadToken, draft);
            return AgentResult<PublicTicketAdmission>.Ok(new PublicTicketAdmission(user.Id, draft));
        }
        catch (UploadLimitException ex)
        {
            return AgentResult<PublicTicketAdmission>.From(ex);
        }
    }

    // ---- drafts ----

    private const string UnknownDraftMessage = "Unknown draftId. Use a draftId returned by this interface for this upload link.";

    private sealed record StagedBatch(string DraftId, bool Created, IReadOnlyList<StagedFileInfo> Files);

    private async Task<AgentResult<StagedBatch>> StageInlineAsync(
        string? code, string baseUrl, string clientAddress, string? draftId, IReadOnlyList<InlineFile> files, CancellationToken ct)
    {
        var owner = await ResolveAsync(code, baseUrl, ct);
        if (!owner.IsOk)
        {
            return owner.Refusal<StagedBatch>();
        }

        var decoded = AgentStaging.DecodeInline(files);
        if (!decoded.IsOk)
        {
            return decoded.Refusal<StagedBatch>();
        }

        var user = owner.Value!;
        var totalBytes = decoded.Value!.Sum(x => (long)x.Bytes.Length);
        var opened = await OpenDraftAsync(user, clientAddress, draftId, scratchBytes: totalBytes, ct);
        if (!opened.IsOk)
        {
            return opened.Refusal<StagedBatch>();
        }

        var (draft, created) = opened.Value;
        var ok = false;
        try
        {
            using var lease = concurrency.TryAcquire(UploadConcurrency.AddressKey(clientAddress), UploadConcurrency.DraftKey(draft));
            if (lease is null)
            {
                return AgentResult<StagedBatch>.Refuse(StatusCodes.Status429TooManyRequests, UploadConcurrency.RefusalMessage);
            }

            var staged = new List<StagedFileInfo>();
            foreach (var (name, bytes) in decoded.Value!)
            {
                if (await AgentStaging.CheckSizeAsync(manager, Cfg, draft, ShareManager.UploadPurposeShareFile, bytes.Length, ct) is { } refusal)
                {
                    return refusal.Refusal<StagedBatch>();
                }

                await using var stream = new MemoryStream(bytes, writable: false);
                var result = await AgentStaging.StageAsync(manager, Cfg, user.Id, draft, name, stream, ShareManager.UploadPurposeShareFile, ct);
                if (!result.IsOk)
                {
                    return result.Refusal<StagedBatch>();
                }

                staged.Add(result.Value!);
            }

            ok = true;
            return AgentResult<StagedBatch>.Ok(new StagedBatch(draft, created, staged));
        }
        finally
        {
            if (!ok)
            {
                await DiscardIfCreatedAsync(user, draft, created);
            }
        }
    }

    /// <summary>
    /// The draft to stage into: one this interface issued for the code (touched, never created), or a new one whose
    /// id is minted here. A new draft counts against the open-draft caps of the code and of the client address; the
    /// scratch and staging budgets are checked first so a refusal opens nothing.
    /// </summary>
    private async Task<AgentResult<(string Draft, bool Created)>> OpenDraftAsync(
        UserAccount user, string clientAddress, string? requestedDraftId, long scratchBytes, CancellationToken ct)
    {
        try
        {
            var requested = requestedDraftId?.Trim();
            if (!string.IsNullOrEmpty(requested))
            {
                if (!IsIssuedDraft(user.UploadToken, requested))
                {
                    return AgentResult<(string, bool)>.BadRequest(UnknownDraftMessage);
                }

                var existing = await manager.EnsurePublicUploadDraftAsync(user.Id, requested, user.UploadToken, clientAddress, ct);
                TouchDraft(user.UploadToken, existing);
                return AgentResult<(string, bool)>.Ok((existing, false));
            }

            scratchSpace.EnsureCanAdmit(scratchBytes);
            manager.GetPublicStageBudget(user.Id);
            var minted = Guid.NewGuid().ToString("N");
            var draft = await manager.EnsurePublicUploadDraftAsync(user.Id, minted, user.UploadToken, clientAddress, ct);
            RememberDraft(user.UploadToken, draft);
            return AgentResult<(string, bool)>.Ok((draft, true));
        }
        catch (InvalidOperationException ex)
        {
            return AgentResult<(string, bool)>.BadRequest(ex.Message);
        }
        catch (UploadLimitException ex)
        {
            return AgentResult<(string, bool)>.From(ex);
        }
    }

    private async Task DiscardIfCreatedAsync(UserAccount user, string draft, bool created)
    {
        if (!created)
        {
            return;
        }

        try
        {
            await manager.FinalizeDraftAsync(user.Id, draft, CancellationToken.None);
        }
        catch (Exception)
        {
            // The sweep removes what is left.
        }
    }

    private string MarkerPath(string code, string draftId) =>
        Path.Combine(DraftMarkerRoot, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant(), draftId);

    private void RememberDraft(string code, string draftId)
    {
        var path = MarkerPath(code, draftId);
        // The sweep may remove the (empty) per-code directory between the two calls; one retry covers that.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, []);
                return;
            }
            catch (DirectoryNotFoundException) when (attempt == 0)
            {
            }
        }
    }

    /// <summary>
    /// Marks the draft as active: the marker is swept by its write time, so a draft staged into for longer than the
    /// sweep window must keep its marker fresh or it would stop being accepted while it still exists.
    /// </summary>
    private void TouchDraft(string code, string draftId)
    {
        try
        {
            File.SetLastWriteTimeUtc(MarkerPath(code, draftId), DateTime.UtcNow);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // No marker (or a sweep right now): the draft is simply not accepted again, as before.
        }
    }

    /// <summary>True only for a 32-character hex id this interface minted for this code (a regenerated code starts over).</summary>
    private bool IsIssuedDraft(string code, string? draftId) =>
        draftId is { Length: 32 } && draftId.All(Uri.IsHexDigit) && File.Exists(MarkerPath(code, draftId.ToLowerInvariant()));
}
