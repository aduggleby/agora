namespace Agora.Domain.Entities;

/// <summary>
/// A share link claimed by a pending share creation. The unique index on <see cref="Token"/> makes the claim atomic;
/// the row is removed in the transaction that commits the share, when the creation fails for good, or by the zombie
/// sweep once it is older than the retention.
/// </summary>
public sealed class ShareTokenReservation
{
    public Guid Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public Guid OwnerUserId { get; set; }
    /// <summary>The draft whose submission holds the claim; the same owner submitting the same draft again shares it.</summary>
    public string DraftShareId { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
}
