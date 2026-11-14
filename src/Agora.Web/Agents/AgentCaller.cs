using System.Security.Claims;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Web.Auth;

namespace Agora.Web.Agents;

/// <summary>The owner an agent token acts as: the account, the token (for attribution) and its access level.</summary>
public sealed record AgentCaller(ShareOwner Owner, Guid TokenId, string Level)
{
    public bool CanSeeAll => Level == ApiTokens.AccessLevels.All;

    /// <summary>Token whose shares are in scope: null (every share) at level all, else the caller's own token.</summary>
    public Guid? ScopeTokenId => CanSeeAll ? null : TokenId;

    /// <summary>The caller of an agent token principal, or null for anything else (cookie, capture token).</summary>
    public static AgentCaller? FromPrincipal(ClaimsPrincipal user)
    {
        var level = ApiTokenDefaults.AccessLevel(user);
        return user.TryGetShareOwner(out var owner) && ApiTokenDefaults.TokenId(user) is { } tokenId && ApiTokens.AccessLevels.IsAgentLevel(level)
            ? new AgentCaller(owner, tokenId, level!)
            : null;
    }
}
