namespace Agora.Application.Abstractions;

/// <summary>
/// The configured public origin (<c>Agora:PublicBaseUrl</c>, normalized, no trailing slash) for code that runs
/// without a request, such as background jobs that send emails. <c>null</c> only in Development/E2E, where the
/// setting is optional.
/// </summary>
public interface IPublicOriginProvider
{
    string? ConfiguredOrigin { get; }
}

public static class PublicOriginExtensions
{
    /// <summary>
    /// Absolute link to a share, or the site-relative path when no origin is configured (Development only).
    /// </summary>
    public static string ShareUrl(this IPublicOriginProvider origin, string token)
    {
        var path = $"/s/{token}";
        return origin.ConfiguredOrigin is { Length: > 0 } configured ? configured + path : path;
    }
}
