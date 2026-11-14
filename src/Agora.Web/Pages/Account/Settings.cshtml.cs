using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Application.Utilities;
using Agora.Web.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Account;

[Authorize]
public class SettingsModel(AuthService authService, AgoraDbContext db, PublicBaseUrlResolver publicBaseUrls, ApiTokenService apiTokens) : PageModel
{
    public string CurrentEmail { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public string UploadIntakeUrl { get; private set; } = string.Empty;
    public string UploadIntakeUrlPrefix { get; private set; } = string.Empty;
    public string UploadToken { get; private set; } = string.Empty;
    /// <summary>Active API tokens of connected apps (Connected apps card).</summary>
    public IReadOnlyList<ApiTokenSummary> ConnectedApps { get; private set; } = [];

    /// <summary>Whether anonymous AI agents may send files to the upload link (off by default).</summary>
    public bool AllowAgentUploads { get; private set; }
    /// <summary>Instructions for agents that were given the upload link; empty when there is no code or the switch is off.</summary>
    public string AgentInstructionsUrl { get; private set; } = string.Empty;
    /// <summary>Plaintext of the agent token just created. Only set on the response of the create POST, never stored.</summary>
    public string? NewAgentToken { get; private set; }
    public string NewAgentTokenName { get; private set; } = string.Empty;

    public static string KindLabel(ApiTokenSummary app) =>
        app.ClientId == ApiTokens.AgentClientId ? "Agent token" :
        app.ClientId.StartsWith("mcp:", StringComparison.Ordinal) ? "Agent sign-in" :
        "Capture app";

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        await LoadAsync(userId, ct);
        return Page();
    }

    private async Task LoadAsync(Guid userId, CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        CurrentEmail = email;
        DisplayName = User.FindFirstValue(ClaimTypes.Name) ?? email;
        var token = await authService.GetOrCreateUploadTokenAsync(userId, ct);
        UploadToken = token ?? string.Empty;
        var publicBaseUrl = publicBaseUrls.Resolve(Request);
        UploadIntakeUrlPrefix = $"{publicBaseUrl}/u/";
        UploadIntakeUrl = string.IsNullOrWhiteSpace(token) ? string.Empty : $"{publicBaseUrl}/u/{Uri.EscapeDataString(token)}";
        AllowAgentUploads = await authService.GetAllowAgentUploadsAsync(userId, ct);
        AgentInstructionsUrl = AllowAgentUploads && !string.IsNullOrWhiteSpace(token) ? $"{UploadIntakeUrl}/llms.txt" : string.Empty;
        ConnectedApps = await apiTokens.ListForUserAsync(userId, ct);
        ViewData["Title"] = "Account Settings";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }

    public async Task<IActionResult> OnPostChangeEmailAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var newEmail = (Request.Form["newEmail"].ToString() ?? string.Empty).Trim();
        var currentPassword = Request.Form["currentPasswordForEmail"].ToString();
        var confirmationUrlBase = $"{publicBaseUrls.Resolve(Request)}/auth/confirm-email-change";

        var result = await authService.RequestEmailChangeAsync(userId, newEmail, currentPassword, confirmationUrlBase, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Confirm your new email to complete the change" });
    }

    public async Task<IActionResult> OnPostUpdateProfileAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var displayName = Request.Form["displayName"].ToString();
        var result = await authService.SetDisplayNameAsync(userId, displayName, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        // Re-issue the cookie from the database record (role, stamp), never from the existing claims, and only if the
        // current cookie still carries the live stamp.
        if (!await CookieSessions.TryReissueAsync(HttpContext, db, ct))
        {
            return Redirect("/login");
        }

        return RedirectToPage("/Account/Settings", new { msg = "Profile updated" });
    }

    public async Task<IActionResult> OnPostChangePasswordAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var currentPassword = Request.Form["currentPasswordForPassword"].ToString();
        var newPassword = Request.Form["newPassword"].ToString();
        var confirmPassword = Request.Form["confirmPassword"].ToString();

        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            return RedirectToPage("/Account/Settings", new { msg = "New passwords do not match" });
        }

        var confirmationUrlBase = $"{publicBaseUrls.Resolve(Request)}/auth/confirm-password-change";
        var result = await authService.RequestPasswordChangeAsync(userId, currentPassword, newPassword, confirmationUrlBase, ct);
        return RedirectToPage("/Account/Settings", new { msg = result.Success ? "Check your email to confirm the password change" : result.Error });
    }

    public async Task<IActionResult> OnPostRegenerateUploadLinkAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var token = await authService.RegenerateUploadTokenAsync(userId, ct);
        if (string.IsNullOrWhiteSpace(token))
        {
            return RedirectToPage("/Account/Settings", new { msg = "Unable to regenerate upload link" });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Upload link regenerated" });
    }

    public async Task<IActionResult> OnPostSetUploadLinkAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var requestedToken = Request.Form["uploadToken"].ToString();
        var result = await authService.SetUploadTokenAsync(userId, requestedToken, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Upload link updated" });
    }

    public async Task<IActionResult> OnPostRevokeAppAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var revoked = Guid.TryParse(Request.Form["tokenId"].ToString(), out var tokenId) &&
                      await apiTokens.RevokeAsync(tokenId, userId, ct);
        return RedirectToPage("/Account/Settings", null, new { msg = revoked ? "App disconnected" : "Unable to disconnect the app" }, "connected-apps");
    }

    public async Task<IActionResult> OnPostCreateAgentTokenAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var name = Request.Form["agentName"].ToString().Trim();
        var token = name.Length == 0
            ? null
            : await apiTokens.CreateAgentTokenAsync(userId, User.FindFirstValue(CookieSessions.SecurityStampClaim), name, Request.Form["accessLevel"].ToString(), ct);
        if (token is null)
        {
            return RedirectToPage("/Account/Settings", null, new { msg = name.Length == 0 ? "Enter a name for the agent token" : "Unable to create the agent token" }, "connected-apps");
        }

        // Rendered directly: no redirect and no TempData, so the plaintext is never stored or put in a URL.
        await LoadAsync(userId, ct);
        NewAgentToken = token;
        NewAgentTokenName = ApiTokens.SanitizeDeviceName(name);
        Response.Headers.CacheControl = "no-store";
        return Page();
    }

    public async Task<IActionResult> OnPostSetAppAccessAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var changed = Guid.TryParse(Request.Form["tokenId"].ToString(), out var tokenId) &&
                      await apiTokens.SetAccessLevelAsync(tokenId, userId, Request.Form["accessLevel"].ToString(), ct);
        return RedirectToPage("/Account/Settings", null, new { msg = changed ? "Access updated" : "Unable to update access" }, "connected-apps");
    }

    public async Task<IActionResult> OnPostSetAgentUploadsAsync(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var allow = string.Equals(Request.Form["allowAgentUploads"].ToString(), "true", StringComparison.Ordinal);
        var saved = await authService.SetAllowAgentUploadsAsync(userId, allow, ct);
        return RedirectToPage("/Account/Settings", null, new { msg = saved ? (allow ? "AI agents can send files to your upload link" : "AI agents can no longer send files to your upload link") : "Unable to update the setting" }, "upload-link-settings");
    }
}
