namespace Agora.Web.Endpoints;

/// <summary>
/// Marks the <c>/api/v1</c> endpoints of connected apps. Only on these does the default authentication scheme accept an
/// API bearer token, and the CSRF middleware never runs antiforgery on them: callers authenticated by
/// <see cref="Auth.ApiTokenDefaults.AuthenticationScheme"/> carry no ambient browser authority, and the anonymous token
/// exchange is protected by PKCE instead.
/// </summary>
public sealed class ApiEndpointMetadata
{
    public static readonly ApiEndpointMetadata Instance = new();

    private ApiEndpointMetadata()
    {
    }
}
