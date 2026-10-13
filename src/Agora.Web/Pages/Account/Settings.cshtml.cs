using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Web.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Account;

[Authorize]
public class SettingsModel(AuthService authService, AgoraDbContext db, PublicBaseUrlResolver publicBaseUrls) : PageModel
{
    public string CurrentEmail { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public string UploadIntakeUrl { get; private set; } = string.Empty;
    public string UploadIntakeUrlPrefix { get; private set; } = string.Empty;
    public string UploadToken { get; private set; } = string.Empty;

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return RedirectToPage("/Login");
        }

        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        CurrentEmail = email;
        DisplayName = User.FindFirstValue(ClaimTypes.Name) ?? email;
        var token = await authService.GetOrCreateUploadTokenAsync(userId, ct);
        UploadToken = token ?? string.Empty;
        var publicBaseUrl = publicBaseUrls.Resolve(Request);
        UploadIntakeUrlPrefix = $"{publicBaseUrl}/u/";
        UploadIntakeUrl = string.IsNullOrWhiteSpace(token) ? string.Empty : $"{publicBaseUrl}/u/{Uri.EscapeDataString(token)}";
        ViewData["Title"] = "Account Settings";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
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
}
