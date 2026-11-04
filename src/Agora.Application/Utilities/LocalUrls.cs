namespace Agora.Application.Utilities;

/// <summary>
/// Validates a post-sign-in return target so <c>/login</c> can never be turned into an open redirect: only a path on
/// this site is accepted.
/// </summary>
public static class LocalUrls
{
    public const int MaxLength = 4096;

    /// <summary>
    /// True for a site-relative path: starts with a single <c>/</c> (not <c>//</c> or <c>/\</c>, which browsers treat
    /// as another host), contains no backslash, whitespace or control characters and is at most <see cref="MaxLength"/>.
    /// </summary>
    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url) || url.Length > MaxLength || url[0] != '/')
        {
            return false;
        }

        if (url.Length > 1 && url[1] is '/' or '\\')
        {
            return false;
        }

        foreach (var ch in url)
        {
            if (ch == '\\' || char.IsControl(ch) || char.IsWhiteSpace(ch))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><paramref name="url"/> when it is local, otherwise <paramref name="fallback"/>.</summary>
    public static string OrDefault(string? url, string fallback = "/") => IsLocal(url) ? url! : fallback;
}
