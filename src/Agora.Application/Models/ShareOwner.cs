using Agora.Application.Utilities;

namespace Agora.Application.Models;

/// <summary>
/// The account a share or account template belongs to: the user id from the session plus the (normalized) email
/// for display. Rows are matched on <see cref="UserId"/> only; the email never authorizes anything.
/// </summary>
public sealed record ShareOwner(Guid UserId, string Email)
{
    public static ShareOwner For(Guid userId, string email) => new(userId, EmailAddress.Normalize(email));

    /// <summary>In-memory form of the ownership predicate the queries use.</summary>
    public bool Owns(Guid? ownerUserId) => ownerUserId == UserId;
}
