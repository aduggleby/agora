using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Auth;

/// <summary>The account behind a valid bearer token, as the authentication handler turns it into a principal.</summary>
public sealed record ApiTokenIdentity(Guid TokenId, Guid UserId, string Email, string DisplayName, string? AccessLevel = null);

/// <summary>An active token as listed under Settings > Connected apps.</summary>
public sealed record ApiTokenSummary(Guid Id, string ClientId, string DeviceName, string? TokenPrefix, DateTime ConnectedAtUtc, DateTime? LastUsedAtUtc, string? AccessLevel = null);

/// <summary>The outcome of a code exchange: the plaintext token (shown once) or an RFC 6749 error code.</summary>
public sealed record ApiTokenExchangeResult(string? AccessToken, Guid TokenId, string? Email, string? Error)
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidGrant = "invalid_grant";

    public bool Success => AccessToken is not null;

    public static ApiTokenExchangeResult Failed(string error) => new(null, Guid.Empty, null, error);
}

/// <summary>
/// Issues, validates and revokes the bearer tokens of connected apps. A pending row is created on consent with the
/// hash of a short-lived authorization code; the first exchange attempt burns the code, and a successful one stores
/// the hash of a new token. A token works while it is not revoked, its user is enabled with the security stamp it was
/// issued under, and it was used within <see cref="IdleLifetime"/>.
/// </summary>
public sealed class ApiTokenService(AgoraDbContext db, TimeProvider? timeProvider = null)
{
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan IdleLifetime = TimeSpan.FromDays(180);
    /// <summary><see cref="ApiToken.LastUsedAtUtc"/> is written at most this often, so API calls rarely write.</summary>
    public static readonly TimeSpan LastUsedResolution = TimeSpan.FromMinutes(15);
    /// <summary>How long revoked and expired rows are kept before cleanup deletes them.</summary>
    public static readonly TimeSpan DeadRowRetention = TimeSpan.FromDays(30);

    /// <summary>Stored <see cref="ApiToken.ClientId"/> prefix of MCP clients (a hash of their registered client id follows).</summary>
    public const string McpClientIdPrefix = "mcp:";

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    private DateTime NowUtc => _time.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Records the user's consent and returns the plaintext authorization code, or null when the user does not exist,
    /// is disabled, or <paramref name="sessionSecurityStamp"/> (the stamp in the consenting session's cookie) is not
    /// the user's current stamp. The last check matters: a cookie stolen before a password reset is still accepted
    /// until its next revalidation, and must not be able to mint a token bound to the new stamp. The inputs must
    /// already be validated (client id, redirect URI, S256 challenge); the device name is sanitized here. The capture
    /// app never gets an access level (it stays null); any other client stores <paramref name="accessLevel"/>, and a
    /// missing or unknown value becomes <see cref="ApiTokens.AccessLevels.Own"/>.
    /// </summary>
    public async Task<string?> CreatePendingAsync(
        Guid userId,
        string? sessionSecurityStamp,
        string clientId,
        string? deviceName,
        string codeChallenge,
        string redirectUri,
        CancellationToken cancellationToken,
        string? accessLevel = null)
    {
        var isCapture = string.Equals(clientId, ApiTokens.CaptureClientId, StringComparison.Ordinal);
        if (!isCapture && !clientId.StartsWith(McpClientIdPrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException("Unknown client id.", nameof(clientId));
        }

        if (!ApiTokens.IsValidCodeChallenge(codeChallenge))
        {
            throw new ArgumentException("The code challenge is not a valid S256 challenge.", nameof(codeChallenge));
        }

        if (!ApiTokens.IsValidRedirectUri(redirectUri))
        {
            throw new ArgumentException("The redirect URI is not a loopback callback.", nameof(redirectUri));
        }

        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null || !user.IsEnabled || string.IsNullOrEmpty(user.SecurityStamp) ||
            !string.Equals(sessionSecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            return null;
        }

        var now = NowUtc;
        var code = ApiTokens.NewCode();
        db.ApiTokens.Add(new ApiToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ClientId = clientId,
            DeviceName = ApiTokens.SanitizeDeviceName(deviceName),
            AuthCodeHash = ApiTokens.Hash(code),
            AuthCodeExpiresAtUtc = now.Add(CodeLifetime),
            CodeChallenge = codeChallenge,
            RedirectUri = redirectUri,
            IssuedSecurityStamp = user.SecurityStamp,
            CreatedAtUtc = now,
            AccessLevel = isCapture ? null : ApiTokens.AccessLevels.NormalizeOrOwn(accessLevel)
        });
        await db.SaveChangesAsync(cancellationToken);
        return code;
    }

    /// <summary>
    /// Creates an active agent token for a headless agent (Settings > Create agent token) and returns the plaintext
    /// (shown once), or null when the user is gone or disabled or <paramref name="sessionSecurityStamp"/> is not the
    /// user's current stamp (same reason as <see cref="CreatePendingAsync"/>). An unknown level becomes "own".
    /// </summary>
    public async Task<string?> CreateAgentTokenAsync(
        Guid userId,
        string? sessionSecurityStamp,
        string? name,
        string? accessLevel,
        CancellationToken cancellationToken)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null || !user.IsEnabled || string.IsNullOrEmpty(user.SecurityStamp) ||
            !string.Equals(sessionSecurityStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            return null;
        }

        var now = NowUtc;
        var token = ApiTokens.NewToken();
        db.ApiTokens.Add(new ApiToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            ClientId = ApiTokens.AgentClientId,
            DeviceName = ApiTokens.SanitizeDeviceName(name),
            TokenHash = ApiTokens.Hash(token),
            TokenPrefix = ApiTokens.DisplayPrefix(token),
            // IsActive requires an exchange time and the issuing stamp; there is no code exchange for these rows.
            ExchangedAtUtc = now,
            IssuedSecurityStamp = user.SecurityStamp,
            CreatedAtUtc = now,
            AccessLevel = ApiTokens.AccessLevels.NormalizeOrOwn(accessLevel)
        });
        await db.SaveChangesAsync(cancellationToken);
        return token;
    }

    /// <summary>
    /// Changes the access level of one of the user's agent tokens. False for an invalid level, an unknown or foreign
    /// id, or a capture app token (null level), which has no level to change.
    /// </summary>
    public async Task<bool> SetAccessLevelAsync(Guid tokenId, Guid userId, string level, CancellationToken cancellationToken)
    {
        if (!ApiTokens.AccessLevels.IsAgentLevel(level))
        {
            return false;
        }

        return await db.ApiTokens
            .Where(x => x.Id == tokenId && x.UserId == userId && x.AccessLevel != null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.AccessLevel, level), cancellationToken) == 1;
    }

    /// <summary>
    /// Exchanges an authorization code for a token. The code is burned by the first attempt whatever its outcome; a
    /// failed check also revokes the pending row. Every mismatch (unknown, used or expired code, wrong verifier,
    /// redirect URI or client, user disabled or re-credentialed since consent) is <c>invalid_grant</c>.
    /// </summary>
    public async Task<ApiTokenExchangeResult> ExchangeAsync(
        string? code,
        string? codeVerifier,
        string? redirectUri,
        string? clientId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(codeVerifier) ||
            string.IsNullOrWhiteSpace(redirectUri) || string.IsNullOrWhiteSpace(clientId))
        {
            return ApiTokenExchangeResult.Failed(ApiTokenExchangeResult.InvalidRequest);
        }

        var codeHash = ApiTokens.Hash(code);
        // Atomic claim: of two concurrent exchanges of one code, exactly one clears the hash and continues.
        var row = await db.ApiTokens.AsNoTracking().SingleOrDefaultAsync(x => x.AuthCodeHash == codeHash, cancellationToken);
        if (row is null ||
            await db.ApiTokens
                .Where(x => x.Id == row.Id && x.AuthCodeHash == codeHash)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.AuthCodeHash, (string?)null), cancellationToken) != 1)
        {
            return ApiTokenExchangeResult.Failed(ApiTokenExchangeResult.InvalidGrant);
        }

        var now = NowUtc;
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.UserId, cancellationToken);
        var valid = row.RevokedAtUtc is null &&
                    row.TokenHash is null &&
                    row.AuthCodeExpiresAtUtc is { } expiresAt && now < expiresAt &&
                    string.Equals(row.ClientId, clientId, StringComparison.Ordinal) &&
                    string.Equals(row.RedirectUri, redirectUri, StringComparison.Ordinal) &&
                    ApiTokens.VerifyPkce(codeVerifier, row.CodeChallenge) &&
                    IsIssuerStampLive(row, user);
        if (!valid)
        {
            await db.ApiTokens
                .Where(x => x.Id == row.Id && x.RevokedAtUtc == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, now), cancellationToken);
            return ApiTokenExchangeResult.Failed(ApiTokenExchangeResult.InvalidGrant);
        }

        var token = ApiTokens.NewToken();
        var tokenHash = ApiTokens.Hash(token);
        var prefix = ApiTokens.DisplayPrefix(token);
        var issued = await db.ApiTokens
            .Where(x => x.Id == row.Id && x.TokenHash == null && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.TokenHash, tokenHash)
                .SetProperty(x => x.TokenPrefix, prefix)
                .SetProperty(x => x.ExchangedAtUtc, now), cancellationToken);
        return issued == 1
            ? new ApiTokenExchangeResult(token, row.Id, user!.Email, null)
            : ApiTokenExchangeResult.Failed(ApiTokenExchangeResult.InvalidGrant);
    }

    /// <summary>
    /// The account behind <paramref name="token"/>, or null when the token is malformed, unknown, revoked, idle for
    /// longer than <see cref="IdleLifetime"/>, or its user is disabled or has a different security stamp now.
    /// </summary>
    public async Task<ApiTokenIdentity?> ValidateAsync(string? token, CancellationToken cancellationToken)
    {
        if (!ApiTokens.IsWellFormedToken(token))
        {
            return null;
        }

        var tokenHash = ApiTokens.Hash(token!);
        var match = await db.ApiTokens.AsNoTracking()
            .Where(x => x.TokenHash == tokenHash)
            .Join(db.Users.AsNoTracking(), t => t.UserId, u => u.Id, (t, u) => new { Token = t, User = u })
            .SingleOrDefaultAsync(cancellationToken);
        if (match is null)
        {
            return null;
        }

        var now = NowUtc;
        var row = match.Token;
        if (!IsActive(row, match.User, now))
        {
            return null;
        }

        if (row.LastUsedAtUtc is not { } lastUsed || now - lastUsed >= LastUsedResolution || lastUsed > now)
        {
            await db.ApiTokens
                .Where(x => x.Id == row.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.LastUsedAtUtc, now), cancellationToken);
        }

        var user = match.User;
        var displayName = string.IsNullOrWhiteSpace(user.DisplayName) ? user.Email : user.DisplayName.Trim();
        return new ApiTokenIdentity(row.Id, user.Id, user.Email, displayName, row.AccessLevel);
    }

    /// <summary>
    /// Revokes one of the user's tokens (or pending consents). True when the token belongs to the user, including when
    /// it was already revoked; false for someone else's or an unknown id.
    /// </summary>
    public async Task<bool> RevokeAsync(Guid tokenId, Guid userId, CancellationToken cancellationToken)
    {
        var now = NowUtc;
        var revoked = await db.ApiTokens
            .Where(x => x.Id == tokenId && x.UserId == userId && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.RevokedAtUtc, now)
                .SetProperty(x => x.AuthCodeHash, (string?)null), cancellationToken);
        return revoked > 0 || await db.ApiTokens.AnyAsync(x => x.Id == tokenId && x.UserId == userId, cancellationToken);
    }

    /// <summary>The user's working tokens, newest connection first.</summary>
    public async Task<IReadOnlyList<ApiTokenSummary>> ListForUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return [];
        }

        var now = NowUtc;
        var rows = await db.ApiTokens.AsNoTracking()
            .Where(x => x.UserId == userId && x.TokenHash != null && x.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);
        return rows
            .Where(x => IsActive(x, user, now))
            .OrderByDescending(x => x.ExchangedAtUtc)
            // SQL Server (datetime2) and SQLite read timestamps back with Kind=Unspecified; they are stored as UTC, and
            // the page formats them with "O", which only appends Z for Kind=Utc.
            .Select(x => new ApiTokenSummary(x.Id, x.ClientId, x.DeviceName, x.TokenPrefix, AsUtc(x.ExchangedAtUtc!.Value), x.LastUsedAtUtc is { } used ? AsUtc(used) : null, x.AccessLevel))
            .ToList();
    }

    /// <summary>
    /// Recurring cleanup: revokes tokens whose user's stamp has moved on, then deletes pending rows whose code expired
    /// and rows revoked or idle-expired for longer than <see cref="DeadRowRetention"/>. Returns the deleted row count.
    /// </summary>
    public async Task<int> CleanupAsync(CancellationToken cancellationToken)
    {
        var now = NowUtc;
        await db.ApiTokens
            .Where(x => x.RevokedAtUtc == null &&
                        !db.Users.Any(u => u.Id == x.UserId && u.IsEnabled && u.SecurityStamp == x.IssuedSecurityStamp))
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, now), cancellationToken);

        var deadBefore = now - DeadRowRetention;
        var idleBefore = now - IdleLifetime - DeadRowRetention;
        return await db.ApiTokens
            .Where(x => (x.TokenHash == null && x.AuthCodeExpiresAtUtc < now) ||
                        x.RevokedAtUtc < deadBefore ||
                        (x.ExchangedAtUtc != null && (x.LastUsedAtUtc ?? x.ExchangedAtUtc) < idleBefore))
            .ExecuteDeleteAsync(cancellationToken);
    }

    private static DateTime AsUtc(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc);

    private static bool IsActive(ApiToken row, UserAccount user, DateTime nowUtc) =>
        row.RevokedAtUtc is null &&
        row.ExchangedAtUtc is { } exchangedAt &&
        nowUtc - (row.LastUsedAtUtc ?? exchangedAt) <= IdleLifetime &&
        IsIssuerStampLive(row, user);

    private static bool IsIssuerStampLive(ApiToken row, UserAccount? user) =>
        user is { IsEnabled: true } &&
        !string.IsNullOrEmpty(user.SecurityStamp) &&
        string.Equals(row.IssuedSecurityStamp, user.SecurityStamp, StringComparison.Ordinal);
}
