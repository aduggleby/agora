using System.Text.RegularExpressions;

namespace Agora.Application.Utilities;

/// <summary>
/// Rewrites share, upload and confirmation tokens inside free text (request paths, query strings, redirect targets)
/// to the same non-reversible reference <see cref="LogSafe.Token"/> produces, so log lines can be correlated without
/// carrying the token. Idempotent: already redacted values are left alone.
/// </summary>
public static partial class TokenRedaction
{
    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var result = QueryTokens().Replace(text, m => $"{m.Groups["key"].Value}={LogSafe.Token(Uri.UnescapeDataString(m.Groups["value"].Value))}");
        return PathTokens().Replace(result, m => $"{m.Groups["prefix"].Value}{LogSafe.Token(Uri.UnescapeDataString(m.Groups["value"].Value))}");
    }

    // token=, uploadToken=, shareToken=, t= (any case) followed by the value, up to the next separator.
    [GeneratedRegex(@"(?<key>\b(?:token|uploadToken|shareToken|t))=(?!tok:)(?<value>[^&\s""'<>]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex QueryTokens();

    // /s/{token}, /u/{token}, /shares/created/{token} path segments.
    [GeneratedRegex(@"(?<prefix>/(?:s|u|shares/created)/)(?!tok:)(?<value>[^/?#&\s""'<>]+)", RegexOptions.CultureInvariant)]
    private static partial Regex PathTokens();
}
