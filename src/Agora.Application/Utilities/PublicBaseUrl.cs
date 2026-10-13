namespace Agora.Application.Utilities;

/// <summary>
/// Validates <c>Agora:PublicBaseUrl</c> (env <c>Agora__PublicBaseUrl</c>), the origin every link that leaves the
/// browser (emails, share links, Open Graph tags) is built from. It is never derived from the request host.
/// </summary>
public static class PublicBaseUrl
{
    public const string Key = "Agora:PublicBaseUrl";

    /// <summary>
    /// Returns the normalized origin (scheme, host and port, no trailing slash), or <c>null</c> when the setting is empty.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the value is not an absolute http(s) URL or carries a path, query, fragment or user info.
    /// </exception>
    public static string? Normalize(string? value)
    {
        var raw = value?.Trim();
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || uri.AbsolutePath != "/"
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || uri.UserInfo.Length > 0)
        {
            throw new InvalidOperationException(
                $"Invalid {Key} (env Agora__PublicBaseUrl) '{raw}': expected an absolute http(s) URL without a path, " +
                "query or fragment, for example 'https://files.example.com'.");
        }

        return uri.GetLeftPart(UriPartial.Authority);
    }

    /// <summary>
    /// Like <see cref="Normalize"/>, but an empty value is a startup error when <paramref name="required"/> is set.
    /// </summary>
    public static string? Resolve(string? value, bool required)
    {
        var normalized = Normalize(value);
        if (normalized is null && required)
        {
            throw new InvalidOperationException(
                $"{Key} (env Agora__PublicBaseUrl) is not configured. Set it to the public origin of this site, for example " +
                "'https://files.example.com'. It is only optional in the Development and E2E environments.");
        }

        return normalized;
    }
}
