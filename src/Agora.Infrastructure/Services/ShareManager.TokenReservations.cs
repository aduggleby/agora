using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Services;

/// <summary>
/// Claims for share links chosen at submission. A link is only a committed <see cref="Share"/> row once the queued job
/// finishes, so the claim is taken in the request path and held until that commit (or a terminal failure).
/// </summary>
public sealed partial class ShareManager
{
    public enum TokenReservationOutcome
    {
        /// <summary>This call created the claim.</summary>
        Reserved,
        /// <summary>The same owner already holds the claim for the same draft (a repeated submission).</summary>
        AlreadyHeld,
        /// <summary>A committed share or another owner's (or draft's) claim has the link.</summary>
        Taken
    }

    /// <summary>
    /// Claims <paramref name="token"/> for one submission. The unique index decides a race: the loser sees the winner's
    /// row on the re-read and is reported as taken, whatever the provider's duplicate-key error looks like.
    /// </summary>
    public async Task<TokenReservationOutcome> ReserveShareTokenAsync(string token, Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        if (await db.Shares.AsNoTracking().AnyAsync(x => x.ShareToken == token, cancellationToken))
        {
            return TokenReservationOutcome.Taken;
        }

        var existing = await FindReservationAsync(token, cancellationToken);
        if (existing is not null)
        {
            return IsHeldBy(existing, ownerUserId, draftShareId) ? TokenReservationOutcome.AlreadyHeld : TokenReservationOutcome.Taken;
        }

        var reservation = new ShareTokenReservation
        {
            Id = Guid.NewGuid(),
            Token = token,
            OwnerUserId = ownerUserId,
            DraftShareId = draftShareId,
            CreatedAtUtc = DateTime.UtcNow
        };
        db.ShareTokenReservations.Add(reservation);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return TokenReservationOutcome.Reserved;
        }
        catch (DbUpdateException)
        {
            // The provider's error text quotes the token, so it is neither logged nor passed on.
            db.Entry(reservation).State = EntityState.Detached;
            var winner = await FindReservationAsync(token, cancellationToken);
            if (winner is null)
            {
                throw new InvalidOperationException("The share link could not be reserved right now.");
            }

            return IsHeldBy(winner, ownerUserId, draftShareId) ? TokenReservationOutcome.AlreadyHeld : TokenReservationOutcome.Taken;
        }
    }

    /// <summary>
    /// Drops the claim after the share row is committed. Separate from the insert on purpose: a claim that is already
    /// gone (swept, released) must not fail a commit that succeeded, and a leftover is harmless (the share holds the
    /// link) and swept later.
    /// </summary>
    private async Task TryReleaseCommittedClaimAsync(string token, Guid ownerUserId)
    {
        try
        {
            await ReleaseShareTokenReservationAsync(token, ownerUserId, CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to release the claim on share {TokenRef} after creating it; the zombie sweep will", LogSafe.Token(token));
        }
    }

    /// <summary>Removes the owner's claim on the token, if any. Never throws for a missing claim.</summary>
    public async Task ReleaseShareTokenReservationAsync(string token, Guid ownerUserId, CancellationToken cancellationToken)
    {
        await db.ShareTokenReservations
            .Where(x => x.Token == token && x.OwnerUserId == ownerUserId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    /// <summary>Removes the claim only when it belongs to this draft (the request path undoing its own claim).</summary>
    public async Task ReleaseShareTokenReservationAsync(string token, Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        await db.ShareTokenReservations
            .Where(x => x.Token == token && x.OwnerUserId == ownerUserId && x.DraftShareId == draftShareId)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private Task<ShareTokenReservation?> FindReservationAsync(string token, CancellationToken cancellationToken) =>
        db.ShareTokenReservations.AsNoTracking().FirstOrDefaultAsync(x => x.Token == token, cancellationToken);

    private static bool IsHeldBy(ShareTokenReservation reservation, Guid ownerUserId, string draftShareId) =>
        reservation.OwnerUserId == ownerUserId && string.Equals(reservation.DraftShareId, draftShareId, StringComparison.Ordinal);

    private Task<int> SweepStaleShareTokenReservationsAsync(DateTime cutoffUtc, CancellationToken cancellationToken) =>
        db.ShareTokenReservations.Where(x => x.CreatedAtUtc <= cutoffUtc).ExecuteDeleteAsync(cancellationToken);
}
