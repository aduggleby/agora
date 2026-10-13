using System.Security.Claims;
using Agora.Application.Models;

namespace Agora.Web.Auth;

/// <summary>The <see cref="ShareOwner"/> of the signed-in user: the id and email claims of the session cookie.</summary>
public static class ShareOwners
{
    public static bool TryGetShareOwner(this ClaimsPrincipal principal, out ShareOwner owner)
    {
        var email = principal.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        if (string.IsNullOrWhiteSpace(email) || !Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            owner = null!;
            return false;
        }

        owner = ShareOwner.For(userId, email);
        return true;
    }

    /// <summary>The signed-in user's id from the session, or null when the principal carries no usable id claim.</summary>
    public static Guid? UserId(this ClaimsPrincipal principal) =>
        Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) ? userId : null;
}
