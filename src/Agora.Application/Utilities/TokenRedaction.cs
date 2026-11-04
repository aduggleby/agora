using System.Text.RegularExpressions;

namespace Agora.Application.Utilities;

/// <summary>
/// Rewrites share, upload and confirmation tokens inside free text (request paths, query strings, redirect targets)
/// to the same non-reversible reference <see cref="LogSafe.Token"/> produces, so log lines can be correlated without
/// carrying the token. API bearer tokens (<c>agora_pat_...</c>) and the authorization code and PKCE verifier of the
/// app sign-in flow are covered too, wherever they appear (headers, query strings, JSON bodies). Idempotent: already
/// redacted values are left alone.
/// </summary>
public static partial class TokenRedaction
{
    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var result = ApiBearerTokens().Replace(text, m => $"{ApiTokens.TokenPrefix}{LogSafe.Token(m.Groups["value"].Value)}");
        result = JsonSecrets().Replace(result, m => $"{m.Groups["key"].Value}{LogSafe.Token(m.Groups["value"].Value)}");
        result = QueryTokens().Replace(result, m => $"{m.Groups["key"].Value}={LogSafe.Token(Uri.UnescapeDataString(m.Groups["value"].Value))}");
        return PathTokens().Replace(result, m => $"{m.Groups["prefix"].Value}{LogSafe.Token(Uri.UnescapeDataString(m.Groups["value"].Value))}");
    }

    // agora_pat_ followed by the secret part, anywhere (for example "Bearer agora_pat_...").
    [GeneratedRegex(@"agora_pat_(?!tok:)(?<value>[A-Za-z0-9_-]+)", RegexOptions.CultureInvariant)]
    private static partial Regex ApiBearerTokens();

    // "code": "...", "code_verifier": "...", "access_token": "..." in a JSON body.
    [GeneratedRegex(@"(?<key>""(?:code|code_verifier|access_token)""\s*:\s*"")(?!tok:)(?<value>[^""]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsonSecrets();

    // token=, uploadToken=, shareToken=, t=, code=, code_verifier=, access_token= (any case) followed by the value, up
    // to the next separator.
    [GeneratedRegex(@"(?<key>\b(?:token|uploadToken|shareToken|t|code|code_verifier|access_token))=(?!tok:)(?<value>[^&\s""'<>]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex QueryTokens();

    // /s/{token}, /u/{token}, /shares/created/{token} path segments.
    [GeneratedRegex(@"(?<prefix>/(?:s|u|shares/created)/)(?!tok:)(?<value>[^/?#&\s""'<>]+)", RegexOptions.CultureInvariant)]
    private static partial Regex PathTokens();
}
