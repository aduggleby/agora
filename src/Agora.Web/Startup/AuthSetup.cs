using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Web.Agents;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

namespace Agora.Web.Startup;

/// <summary>
/// Authentication and authorization wiring. Two credentials exist and never overlap:
/// <list type="bullet">
/// <item>the sign-in cookie, accepted by every page, endpoint, the SignalR hub and Hangfire;</item>
/// <item>the API bearer token of connected apps, accepted only by <c>/api/v1</c> endpoints (<see cref="ApiEndpointMetadata"/>).</item>
/// </list>
/// The default authenticate scheme is a policy scheme that picks the token scheme on every machine route
/// (<see cref="ApiEndpointMetadata"/>, where a session cookie is never read) and the cookie everywhere else, so
/// <c>HttpContext.User</c> is populated before CSRF and rate limiting. Independently, every authorization policy names
/// its scheme (the default and admin policies: cookies; <see cref="ApiTokenDefaults.ApiClientPolicy"/>:
/// the token), and the authorization middleware re-authenticates with exactly those schemes. The anonymous fallback policy
/// names none on purpose and keeps the principal the selector produced.
/// </summary>
public static class AuthSetup
{
    public const string AdminOnlyPolicy = "AdminOnly";
    public const string LoginPath = "/login";
    /// <summary>Query/form name of the post-sign-in return path, shared by the cookie challenge and the login form.</summary>
    public const string ReturnUrlParameter = "returnUrl";

    public static AuthenticationBuilder AddAgoraAuthentication(
        this IServiceCollection services,
        AgoraAuthOptions authOptions,
        CookieSecurePolicy cookieSecurePolicy,
        Action<CookieAuthenticationOptions>? configureCookie = null)
    {
        const string cookies = CookieAuthenticationDefaults.AuthenticationScheme;
        return services
            .AddAuthentication(options =>
            {
                // Only authentication goes through the selector; challenge, forbid, sign-in and sign-out stay on cookies.
                options.DefaultScheme = cookies;
                options.DefaultAuthenticateScheme = ApiTokenDefaults.SelectorScheme;
            })
            .AddPolicyScheme(ApiTokenDefaults.SelectorScheme, "Cookie or API token", options =>
            {
                options.ForwardDefaultSelector = SelectScheme;
            })
            .AddScheme<AuthenticationSchemeOptions, ApiTokenAuthenticationHandler>(ApiTokenDefaults.AuthenticationScheme, _ => { })
            .AddCookie(cookies, options =>
            {
                options.LoginPath = LoginPath;
                options.AccessDeniedPath = LoginPath;
                options.ReturnUrlParameter = ReturnUrlParameter;
                options.ExpireTimeSpan = CookieSessions.SessionLifetime(authOptions);
                options.SlidingExpiration = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = cookieSecurePolicy;
                options.Events.OnValidatePrincipal = CookieSessions.ValidatePrincipalAsync;
                // An app (any bearer credential) cannot follow a login redirect: answer 401/403 JSON instead.
                var redirectToLogin = options.Events.OnRedirectToLogin;
                options.Events.OnRedirectToLogin = context => ApiTokenDefaults.HasBearerHeader(context.Request)
                    ? ApiTokenDefaults.WriteUnauthorizedAsync(context.Response, "This endpoint does not accept API tokens.")
                    : redirectToLogin(context);
                var redirectToAccessDenied = options.Events.OnRedirectToAccessDenied;
                options.Events.OnRedirectToAccessDenied = context => ApiTokenDefaults.HasBearerHeader(context.Request)
                    ? ApiTokenDefaults.WriteForbiddenAsync(context.Response)
                    : redirectToAccessDenied(context);
                configureCookie?.Invoke(options);
            });
    }

    /// <summary>
    /// The API token scheme for every endpoint marked <see cref="ApiEndpointMetadata"/> (routing has already selected
    /// the endpoint); without a bearer it yields no principal, so a session cookie is never read there and cannot be
    /// refreshed (no sliding-expiration Set-Cookie on machine routes). Cookies everywhere else, so a token presented to
    /// any other endpoint is simply ignored.
    /// </summary>
    public static string SelectScheme(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<ApiEndpointMetadata>() is not null
            ? ApiTokenDefaults.AuthenticationScheme
            : CookieAuthenticationDefaults.AuthenticationScheme;

    public static void ConfigureAuthorization(AuthorizationOptions options)
    {
        const string cookies = CookieAuthenticationDefaults.AuthenticationScheme;
        // [Authorize] and RequireAuthorization(): a signed-in cookie user.
        options.DefaultPolicy = new AuthorizationPolicyBuilder(cookies).RequireAuthenticatedUser().Build();
        // Endpoints without authorization metadata stay anonymous. No scheme on purpose: the principal is the one the selector
        // (SelectScheme) produced: the cookie on ordinary endpoints, and never the cookie on machine routes (ApiEndpointMetadata),
        // where reading it would also refresh it with a Set-Cookie.
        options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();
        options.AddPolicy(AdminOnlyPolicy, policy => policy.AddAuthenticationSchemes(cookies).RequireRole("admin"));
        options.AddPolicy(ApiTokenDefaults.ApiClientPolicy, policy => policy
            .AddAuthenticationSchemes(ApiTokenDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(context => ApiTokenDefaults.IsApiTokenPrincipal(context.User)));
        options.AddPolicy(ApiTokenDefaults.CapturePolicy, policy => policy
            .AddAuthenticationSchemes(ApiTokenDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(context => ApiTokenDefaults.AccessLevel(context.User) == ApiTokens.AccessLevels.Capture));
        // /mcp: a bearer means an agent token (own or all; a capture token is refused with 403, an invalid one challenged
        // with 401). Without a bearer the only way in is anonymous upload-link mode: exactly one non-empty `upload` value.
        options.AddPolicy(ApiTokenDefaults.AgentMcpPolicy, policy => policy
            .AddAuthenticationSchemes(ApiTokenDefaults.AuthenticationScheme)
            .RequireAssertion(context => context.Resource is HttpContext http &&
                (ApiTokenDefaults.HasBearerHeader(http.Request)
                    ? ApiTokens.AccessLevels.IsAgentLevel(ApiTokenDefaults.AccessLevel(context.User))
                    : McpCaller.UploadCode(http.Request) is not null)));
        options.AddPolicy(ApiTokenDefaults.AgentPolicy, policy => policy
            .AddAuthenticationSchemes(ApiTokenDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireAssertion(context => ApiTokens.AccessLevels.IsAgentLevel(ApiTokenDefaults.AccessLevel(context.User))));
    }
}
