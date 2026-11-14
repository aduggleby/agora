using System.Security.Claims;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Primitives;

namespace Agora.Web.Pages.Connect;

/// <summary>
/// Consent page of the app sign-in flow (OAuth 2.0 authorization code with PKCE and a loopback redirect; contract in
/// <c>docs/api/v1.md</c>). GET validates the request and shows Approve/Deny; the CSRF-protected POST re-validates the
/// same parameters from hidden fields and redirects to the app's loopback callback with a code or an error. An
/// invalid <c>redirect_uri</c> is never redirected to: the page shows the error instead. Two kinds of client: the
/// capture app (<see cref="ApiTokens.CaptureClientId"/>, fixed loopback redirect) and MCP agents with a registered
/// <c>agora_mcp_</c> client id (redirects from their registration; the owner also picks an access level).
/// </summary>
[Authorize]
public class AuthorizeModel(ApiTokenService tokens, OAuthClientCodec clients, PublicBaseUrlResolver publicBaseUrls) : PageModel
{
    public const string ApproveDecision = "approve";
    public const string DenyDecision = "deny";

    public string ClientId { get; private set; } = string.Empty;
    public string RedirectUri { get; private set; } = string.Empty;
    public string State { get; private set; } = string.Empty;
    public string CodeChallenge { get; private set; } = string.Empty;
    public string CodeChallengeMethod { get; private set; } = string.Empty;
    /// <summary>The raw device name as sent by the app (re-posted unchanged).</summary>
    public string DeviceNameRaw { get; private set; } = string.Empty;
    /// <summary>The sanitized device name shown to the user and stored.</summary>
    public string DeviceName { get; private set; } = string.Empty;
    public string Email { get; private set; } = string.Empty;
    /// <summary>True for a registered MCP client; the page then shows its (unverified) name, redirect host and an access choice.</summary>
    public bool IsMcpClient { get; private set; }
    public string RedirectHost { get; private set; } = string.Empty;
    public string Resource { get; private set; } = string.Empty;
    public string Scope { get; private set; } = string.Empty;
    /// <summary>The access level chosen on the page (<see cref="ApiTokens.AccessLevels.Own"/> by default).</summary>
    public string AccessLevel { get; private set; } = ApiTokens.AccessLevels.Own;
    /// <summary>Set when <c>redirect_uri</c> is missing or invalid: the page shows this error and nothing else.</summary>
    public string? Error { get; private set; }

    public Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        ApplyResponseHeaders();
        return Handle(Request.Query, decision: null, ct);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        ApplyResponseHeaders();
        var form = await Request.ReadFormAsync(ct);
        return await Handle(form, form["decision"].ToString(), ct);
    }

    private async Task<IActionResult> Handle(IEnumerable<KeyValuePair<string, StringValues>> source, string? decision, CancellationToken ct)
    {
        var values = source.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        ViewData["Title"] = "Connect an app";
        Email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;

        // 1. The redirect target itself: never redirect to anything that is not an allowed callback.
        TrySingle(values, "client_id", out var requestedClientId);
        var registration = OAuthClients.IsMcpClientId(requestedClientId) ? clients.Decode(requestedClientId) : null;
        IsMcpClient = registration is not null;
        if (OAuthClients.IsMcpClientId(requestedClientId) && registration is null)
        {
            return RedirectError("The app is not registered with this Agora server, so Agora cannot send you back to it. Start the connection again from the app.");
        }

        if (!TrySingle(values, "redirect_uri", out var redirectUri) ||
            !(registration is null
                ? ApiTokens.IsValidRedirectUri(redirectUri)
                : OAuthClients.MatchesRegistered(registration.RedirectUris, redirectUri, clients.AllowedRedirectHosts)))
        {
            return RedirectError("The app sent an invalid redirect address, so Agora cannot send you back to it. Start the connection again from the app.");
        }

        RedirectUri = redirectUri;
        // The Approve/Deny POST is answered with a redirect to the app's callback; allow its origin in this page's form-action.
        // IPv6 literals cannot be written as CSP host sources, so [::1] relies on the policy being report-only.
        if (registration is not null)
        {
            var callback = new Uri(redirectUri);
            RedirectHost = callback.Authority;
            SecurityHeaders.UseReportOnlyPolicyWithFormAction(HttpContext, callback.GetLeftPart(UriPartial.Authority));
        }
        else if (redirectUri.StartsWith("http://127.0.0.1:", StringComparison.Ordinal))
        {
            SecurityHeaders.UseReportOnlyPolicyWithFormAction(HttpContext, redirectUri[..redirectUri.LastIndexOf('/')]);
        }

        // 2. Everything else goes back to the app as error=invalid_request (state echoed only when it is valid).
        var hasState = TrySingle(values, "state", out var state) && ApiTokens.IsValidState(state);
        if (!hasState ||
            !TrySingle(values, "client_id", out var clientId) ||
            !(registration is not null || string.Equals(clientId, ApiTokens.CaptureClientId, StringComparison.Ordinal)) ||
            !TrySingle(values, "code_challenge", out var codeChallenge) || !ApiTokens.IsValidCodeChallenge(codeChallenge) ||
            !TrySingle(values, "code_challenge_method", out var method) || !ApiTokens.IsSupportedChallengeMethod(method) ||
            !TryOptional(values, "device_name", out var deviceName) || deviceName.Length > ApiTokens.MaxRawDeviceNameLength ||
            !TryOptional(values, "resource", out var resource) || !TryOptional(values, "scope", out var scope) ||
            scope.Length > 512)
        {
            return RedirectToApp(redirectUri, ("error", "invalid_request"), ("state", hasState ? state : null));
        }

        if (registration is not null && resource.Length > 0 && !OAuthClients.IsValidResource(resource, publicBaseUrls.Resolve(Request)))
        {
            return RedirectToApp(redirectUri, ("error", "invalid_target"), ("state", state));
        }

        ClientId = clientId;
        State = state;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = method;
        DeviceNameRaw = deviceName;
        DeviceName = registration?.Name ?? ApiTokens.SanitizeDeviceName(deviceName);
        if (registration is not null)
        {
            Resource = resource;
            Scope = scope;
            AccessLevel = decision is null || !TrySingle(values, "accessLevel", out var level)
                ? ApiTokens.AccessLevels.Own
                : ApiTokens.AccessLevels.NormalizeOrOwn(level);
        }

        if (decision is null)
        {
            return Page();
        }

        if (string.Equals(decision, ApproveDecision, StringComparison.Ordinal) && User.UserId() is { } userId)
        {
            var code = registration is null
                ? await tokens.CreatePendingAsync(userId, User.FindFirstValue(CookieSessions.SecurityStampClaim), clientId, deviceName, codeChallenge, redirectUri, ct)
                : await tokens.CreatePendingAsync(userId, User.FindFirstValue(CookieSessions.SecurityStampClaim), OAuthClients.StoredClientId(clientId), DeviceName, codeChallenge, redirectUri, ct, AccessLevel);
            if (code is not null)
            {
                return RedirectToApp(redirectUri, ("code", code), ("state", state));
            }
        }

        // Deny, an unknown decision, or an account that can no longer consent (deleted or disabled meanwhile, or the
        // session's security stamp is stale, for example a cookie stolen before a password reset).
        return RedirectToApp(redirectUri, ("error", "access_denied"), ("state", state));
    }

    private IActionResult RedirectError(string message)
    {
        Error = message;
        Response.StatusCode = StatusCodes.Status400BadRequest;
        return Page();
    }

    private RedirectResult RedirectToApp(string redirectUri, params (string Name, string? Value)[] parameters)
    {
        // redirect_uri is validated to have no query or fragment, so the parameters start a new query string.
        var query = string.Join('&', parameters
            .Where(x => x.Value is not null)
            .Select(x => $"{x.Name}={Uri.EscapeDataString(x.Value!)}"));
        return Redirect($"{redirectUri}?{query}");
    }

    private void ApplyResponseHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Frame-Options"] = "DENY";
    }

    /// <summary>A parameter that must be present exactly once (RFC 6749 section 3.1) and non-empty.</summary>
    private static bool TrySingle(Dictionary<string, StringValues> values, string name, out string value)
    {
        value = string.Empty;
        if (!values.TryGetValue(name, out var raw) || raw.Count != 1 || string.IsNullOrEmpty(raw[0]))
        {
            return false;
        }

        value = raw[0]!;
        return true;
    }

    /// <summary>A parameter that may be absent or empty but not repeated.</summary>
    private static bool TryOptional(Dictionary<string, StringValues> values, string name, out string value)
    {
        value = string.Empty;
        if (!values.TryGetValue(name, out var raw) || raw.Count == 0)
        {
            return true;
        }

        if (raw.Count != 1)
        {
            return false;
        }

        value = raw[0] ?? string.Empty;
        return true;
    }
}
