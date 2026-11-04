namespace Agora.Domain.Entities;

/// <summary>
/// An app's access to one account (the capture app's bearer token). One row covers the whole life cycle: it is
/// created pending with an authorization code on consent, becomes active when the code is exchanged (the code hash is
/// cleared then, so the code is naturally single use) and ends when it is revoked, the user's security stamp changes or
/// it goes unused for too long. Codes and tokens are stored only as SHA-256 hashes.
/// </summary>
public sealed class ApiToken
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    /// <summary>SHA-256 of the bearer token; null until the code is exchanged.</summary>
    public string? TokenHash { get; set; }
    /// <summary>The first characters of the token after its fixed prefix, for display only.</summary>
    public string? TokenPrefix { get; set; }
    /// <summary>SHA-256 of the pending authorization code; cleared on the first exchange attempt.</summary>
    public string? AuthCodeHash { get; set; }
    public DateTime? AuthCodeExpiresAtUtc { get; set; }
    public string CodeChallenge { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    /// <summary>The user's security stamp at consent; any later rotation invalidates the token.</summary>
    public string IssuedSecurityStamp { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? ExchangedAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}
