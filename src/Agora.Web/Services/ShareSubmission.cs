using Agora.Application.Utilities;
using Agora.Infrastructure.Services;

namespace Agora.Web.Services;

/// <summary>The link-claim steps of submitting a share, kept out of the endpoint so they can be tested.</summary>
public static class ShareSubmission
{
    /// <summary>
    /// The refusal for a link the owner asked for, or null when it can be claimed: invalid, taken by a committed share
    /// or another submission's claim, or held by another owner's creation that is still in flight.
    /// </summary>
    public static async Task<string?> RefuseRequestedTokenAsync(
        ShareManager manager, ShareCreationStatusStore status, string token, Guid ownerUserId, string draftShareId, CancellationToken ct)
    {
        var refusal = await manager.CheckRequestedShareTokenAsync(token, ct, ownerUserId, draftShareId);
        if (refusal is null &&
            status.Read(token) is { State: not ("completed" or "failed") } pending && pending.OwnerUserId != ownerUserId)
        {
            refusal = $"That share link is already in use. Try {await manager.GenerateUniqueShareTokenAsync(8, ct)} or choose another.";
        }

        return refusal;
    }

    /// <summary>
    /// Claims the link, then seals the draft and enqueues the job. Returns null when queued, or the refusal text when
    /// the link is taken. The draft already being sealed returns false (409): a queued job of a concurrent submission
    /// holds the claim, so it stays. A claim this call made is released when the seal or enqueue throws (503).
    /// </summary>
    public static async Task<(bool Refused, string? Text, bool Sealed)> ClaimAndSealAsync(
        ShareManager manager, string token, Guid ownerUserId, string draftShareId, Func<Task> enqueue, CancellationToken ct)
    {
        var claim = await manager.ReserveShareTokenAsync(token, ownerUserId, draftShareId, ct);
        if (claim == ShareManager.TokenReservationOutcome.Taken)
        {
            return (true, await manager.CheckRequestedShareTokenAsync(token, ct) ?? "That share link is already in use. Choose another.", false);
        }

        var sealReturned = false;
        try
        {
            var sealedNow = await manager.SealDraftForSubmissionAsync(ownerUserId, draftShareId, enqueue, ct);
            sealReturned = true;
            return (false, null, sealedNow);
        }
        finally
        {
            if (!sealReturned && claim == ShareManager.TokenReservationOutcome.Reserved)
            {
                await manager.ReleaseShareTokenReservationAsync(token, ownerUserId, draftShareId, CancellationToken.None);
            }
        }
    }
}
