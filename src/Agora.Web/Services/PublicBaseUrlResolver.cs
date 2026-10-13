using Agora.Application.Abstractions;

namespace Agora.Web.Services;

/// <summary>
/// The origin every outgoing link (emails, share and upload links, Open Graph tags) is built from. Outside
/// Development and E2E this is always the validated <c>Agora:PublicBaseUrl</c>; the request host is only consulted
/// where startup allowed it, so a spoofed <c>X-Forwarded-Host</c> can never end up in an emailed link.
/// </summary>
public sealed class PublicBaseUrlResolver(string? configured, bool allowRequestHostFallback) : IPublicOriginProvider
{
    /// <summary>Normalized configured origin, or <c>null</c> when unset (Development/E2E only).</summary>
    public string? Configured { get; } = configured;

    string? IPublicOriginProvider.ConfiguredOrigin => Configured;

    public string Resolve(HttpRequest request)
    {
        if (Configured is not null)
        {
            return Configured;
        }

        if (allowRequestHostFallback)
        {
            return $"{request.Scheme}://{request.Host}";
        }

        throw new InvalidOperationException("Agora:PublicBaseUrl (env Agora__PublicBaseUrl) is not configured.");
    }
}
