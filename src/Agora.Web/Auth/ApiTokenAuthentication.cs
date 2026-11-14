using System.Security.Claims;
using System.Text.Encodings.Web;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Agora.Web.Auth;

/// <summary>Names and helpers shared by the API token scheme, the policy scheme and the CSRF middleware.</summary>
public static class ApiTokenDefaults
{
    public const string AuthenticationScheme = "ApiToken";
    /// <summary>The default authenticate scheme: forwards to the API token scheme or to cookies.</summary>
    public const string SelectorScheme = "Smart";
    /// <summary>Authorization policy of the <c>/api/v1</c> endpoints: authenticated by <see cref="AuthenticationScheme"/>.</summary>
    public const string ApiClientPolicy = "ApiClient";
    public const string TokenIdClaim = "agora:token_id";
    /// <summary>Access of an API token principal: <c>capture</c>, <c>own</c> or <c>all</c> (<see cref="ApiTokens.AccessLevels"/>).</summary>
    public const string AccessClaim = "agora:access";
    /// <summary>Policy of the capture endpoints: capture app tokens only.</summary>
    public const string CapturePolicy = "Capture";
    /// <summary>Policy of the agent endpoints: agent tokens (levels own and all) only.</summary>
    public const string AgentPolicy = "Agent";

    private const string BearerPrefix = "Bearer ";

    /// <summary>The token of an <c>Authorization: Bearer agora_pat_...</c> header, or null.</summary>
    public static string? ReadBearerToken(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        return header.StartsWith(BearerPrefix + ApiTokens.TokenPrefix, StringComparison.Ordinal)
            ? header[BearerPrefix.Length..].Trim()
            : null;
    }

    /// <summary>True when the request sends any bearer credential (so it is an app, not a browser that can follow a login redirect).</summary>
    public static bool HasBearerHeader(HttpRequest request) =>
        request.Headers.Authorization.ToString().StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>True for a principal created by <see cref="ApiTokenAuthenticationHandler"/>.</summary>
    public static bool IsApiTokenPrincipal(ClaimsPrincipal principal) =>
        principal.Identity is { IsAuthenticated: true, AuthenticationType: AuthenticationScheme };

    public static ClaimsPrincipal CreatePrincipal(ApiTokenIdentity identity)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, identity.UserId.ToString()),
            new(ClaimTypes.Email, identity.Email),
            new(ClaimTypes.Name, identity.DisplayName),
            new(TokenIdClaim, identity.TokenId.ToString()),
            new(AccessClaim, identity.AccessLevel ?? ApiTokens.AccessLevels.Capture)
        };

        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthenticationScheme));
    }

    /// <summary>The token id of an API token principal, or null.</summary>
    public static Guid? TokenId(ClaimsPrincipal principal) =>
        IsApiTokenPrincipal(principal) && Guid.TryParse(principal.FindFirstValue(TokenIdClaim), out var id) ? id : null;

    /// <summary>The access of an API token principal (<c>capture</c>, <c>own</c>, <c>all</c>), or null.</summary>
    public static string? AccessLevel(ClaimsPrincipal principal) =>
        IsApiTokenPrincipal(principal) ? principal.FindFirstValue(AccessClaim) : null;

    /// <summary>A JSON 401 with <c>WWW-Authenticate: Bearer</c>, never a redirect.</summary>
    public static Task WriteUnauthorizedAsync(HttpResponse response, string error, bool invalidToken = false)
    {
        response.StatusCode = StatusCodes.Status401Unauthorized;
        response.Headers.WWWAuthenticate = invalidToken ? "Bearer error=\"invalid_token\"" : "Bearer";
        response.Headers.CacheControl = "no-store";
        return response.WriteAsJsonAsync(new { error });
    }

    /// <summary>The 401 for an <c>/api/v1</c> request without a working token: "required", or "invalid" when one was sent.</summary>
    public static Task ChallengeAsync(HttpContext context)
    {
        var sentToken = ReadBearerToken(context.Request) is not null;
        return WriteUnauthorizedAsync(
            context.Response,
            sentToken ? "The API token is invalid, revoked or expired; reconnect the app." : "An API token is required.",
            invalidToken: sentToken);
    }

    public static Task WriteForbiddenAsync(HttpResponse response)
    {
        response.StatusCode = StatusCodes.Status403Forbidden;
        response.Headers.CacheControl = "no-store";
        return response.WriteAsJsonAsync(new { error = "This credential cannot be used here." });
    }
}

/// <summary>
/// Authenticates <c>Authorization: Bearer agora_pat_...</c> through <see cref="ApiTokenService.ValidateAsync"/>. The
/// principal carries the same id, email and name claims as the cookie principal (so <c>TryGetShareOwner</c> and
/// <c>ShareManager</c> work unchanged) plus <see cref="ApiTokenDefaults.TokenIdClaim"/>, but no role and no security
/// stamp: it can never satisfy an admin check or be re-issued as a cookie.
/// </summary>
public sealed class ApiTokenAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiTokenService tokens)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = ApiTokenDefaults.ReadBearerToken(Request);
        if (token is null)
        {
            return AuthenticateResult.NoResult();
        }

        var identity = await tokens.ValidateAsync(token, Context.RequestAborted);
        if (identity is null)
        {
            return AuthenticateResult.Fail("Invalid, revoked or expired API token.");
        }

        var principal = ApiTokenDefaults.CreatePrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties) =>
        ApiTokenDefaults.ChallengeAsync(Context);

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties) =>
        ApiTokenDefaults.WriteForbiddenAsync(Response);
}
