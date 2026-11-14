using System.Text.Json.Serialization;

namespace Agora.Application.Utilities;

/// <summary>A dynamically registered OAuth client (RFC 7591), carried inside its own <c>client_id</c>.</summary>
public sealed record OAuthClientRegistration(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("redirect_uris")] IReadOnlyList<string> RedirectUris,
    [property: JsonPropertyName("iat")] long IssuedAtUnixSeconds);

/// <summary>
/// Rules for the OAuth clients of MCP agents: the client id format, the redirect URIs a client may register and how
/// an authorization request's redirect is matched against the registered ones, and the <c>resource</c> check
/// (RFC 8707). The capture app keeps its own fixed rules in <see cref="ApiTokens"/>.
/// </summary>
public static class OAuthClients
{
    public const string ClientIdPrefix = "agora_mcp_";
    /// <summary>DataProtection purpose that protects the registration inside a client id.</summary>
    public const string ProtectorPurpose = "Agora.OAuthClient.v1";
    public const int MaxRedirectUris = 5;
    public const int MaxRedirectUriLength = 200;
    public const int MaxClientNameLength = 200;
    /// <summary>HTTPS redirect hosts that are always trusted (hosted agent connectors); more come from configuration.</summary>
    public static readonly IReadOnlyList<string> DefaultAllowedRedirectHosts = ["claude.ai", "claude.com"];

    public static bool IsMcpClientId(string? clientId) => clientId is not null && clientId.StartsWith(ClientIdPrefix, StringComparison.Ordinal);

    /// <summary>The form stored on <c>ApiToken.ClientId</c>: <c>mcp:</c> plus the first 32 hex characters of SHA-256(client id).</summary>
    public static string StoredClientId(string clientId) => "mcp:" + ApiTokens.Hash(clientId)[..32];

    /// <summary>
    /// Valid at registration: loopback <c>http</c> (127.0.0.1, [::1] or localhost, any port and path) or <c>https</c>
    /// on a trusted host. No userinfo, query or fragment (the consent page appends its own query), at most
    /// <see cref="MaxRedirectUriLength"/> characters.
    /// </summary>
    public static bool IsAllowedRedirectUri(string? redirectUri, IEnumerable<string>? extraAllowedHosts = null)
    {
        if (string.IsNullOrEmpty(redirectUri) || redirectUri.Length > MaxRedirectUriLength ||
            !Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            redirectUri.Contains('?') || redirectUri.Contains('#') || redirectUri.Contains('@') ||
            redirectUri.Any(char.IsWhiteSpace) || redirectUri.Any(char.IsControl))
        {
            return false;
        }

        if (IsLoopback(uri))
        {
            return uri.Scheme == Uri.UriSchemeHttp;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        var host = uri.IdnHost;
        return DefaultAllowedRedirectHosts.Concat(extraAllowedHosts ?? []).Any(x => string.Equals(x, host, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Whether <paramref name="requested"/> is one of the registered URIs: exact for <c>https</c>; for loopback the
    /// port is ignored (RFC 8252 section 7.3). The requested URI must itself be valid.
    /// </summary>
    public static bool MatchesRegistered(IEnumerable<string> registered, string? requested, IEnumerable<string>? extraAllowedHosts = null)
    {
        if (!IsAllowedRedirectUri(requested, extraAllowedHosts) ||
            !Uri.TryCreate(requested, UriKind.Absolute, out var wanted))
        {
            return false;
        }

        foreach (var candidate in registered)
        {
            if (string.Equals(candidate, requested, StringComparison.Ordinal))
            {
                return true;
            }

            if (IsLoopback(wanted) && Uri.TryCreate(candidate, UriKind.Absolute, out var known) && IsLoopback(known) &&
                string.Equals(known.Scheme, wanted.Scheme, StringComparison.Ordinal) &&
                string.Equals(known.IdnHost, wanted.IdnHost, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(known.AbsolutePath, wanted.AbsolutePath, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The resource indicator of an authorize or token request (RFC 8707) names this server: <c>{base}/mcp</c> or
    /// <c>{base}</c>, scheme and host case-insensitive, one trailing slash tolerated.
    /// </summary>
    public static bool IsValidResource(string? resource, string baseUrl)
    {
        if (string.IsNullOrEmpty(resource) || resource.Contains('?') || resource.Contains('#') ||
            !Uri.TryCreate(resource, UriKind.Absolute, out var given) ||
            !Uri.TryCreate(baseUrl, UriKind.Absolute, out var server))
        {
            return false;
        }

        if (!string.Equals(given.Scheme, server.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(given.IdnHost, server.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            given.Port != server.Port || given.UserInfo.Length != 0)
        {
            return false;
        }

        var path = given.AbsolutePath;
        if (path.Length > 1 && path.EndsWith('/'))
        {
            path = path[..^1];
        }

        return path is "/" or "/mcp";
    }

    private static bool IsLoopback(Uri uri) => uri.HostNameType switch
    {
        UriHostNameType.IPv4 => uri.Host == "127.0.0.1",
        UriHostNameType.IPv6 => uri.IdnHost == "[::1]" || uri.Host == "[::1]" || uri.Host == "::1",
        _ => string.Equals(uri.IdnHost, "localhost", StringComparison.OrdinalIgnoreCase)
    };
}
