using System.Text.Json;
using Agora.Application.Utilities;
using Microsoft.AspNetCore.DataProtection;

namespace Agora.Web.Endpoints;

/// <summary>
/// Stateless dynamic client registration: the registration (name, redirect URIs, issue time) is protected with
/// DataProtection and returned as the <c>client_id</c>, so no client rows exist. Ids stay valid while the key ring is
/// kept; a lost ring forces clients to register again (<c>invalid_client</c>).
/// </summary>
public sealed class OAuthClientCodec(IDataProtectionProvider provider, IConfiguration configuration)
{
    private readonly IDataProtector _protector = provider.CreateProtector(OAuthClients.ProtectorPurpose);

    /// <summary>Hosts allowed for <c>https</c> redirects in addition to the built-in ones (<c>Agora:Agents:AllowedRedirectHosts</c>).</summary>
    public IReadOnlyList<string> AllowedRedirectHosts { get; } =
        (configuration.GetSection("Agora:Agents:AllowedRedirectHosts").Get<string[]>() ?? [])
            .SelectMany(x => x.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .ToArray();

    public string Encode(OAuthClientRegistration registration) =>
        OAuthClients.ClientIdPrefix + _protector.Protect(JsonSerializer.Serialize(registration));

    /// <summary>The registration behind a client id, or null when it is malformed, tampered with or from another key ring.</summary>
    public OAuthClientRegistration? Decode(string? clientId)
    {
        if (!OAuthClients.IsMcpClientId(clientId))
        {
            return null;
        }

        try
        {
            var registration = JsonSerializer.Deserialize<OAuthClientRegistration>(_protector.Unprotect(clientId![OAuthClients.ClientIdPrefix.Length..]));
            return registration is { RedirectUris.Count: > 0 } ? registration : null;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or JsonException or FormatException)
        {
            return null;
        }
    }
}
