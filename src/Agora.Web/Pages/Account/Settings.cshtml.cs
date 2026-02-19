using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Agora.Application.Models;

namespace Agora.Web.Pages.Account;

[Authorize]
public class SettingsModel(AuthService authService, IOptions<AgoraOptions> options) : PageModel
{
    public string CurrentEmail { get; private set; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public string UploadIntakeUrl { get; private set; } = string.Empty;
    public string UploadIntakeUrlPrefix { get; private set; } = string.Empty;
    public string UploadToken { get; private set; } = string.Empty;

    public async Task OnGet(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        CurrentEmail = email;
        DisplayName = User.FindFirstValue(ClaimTypes.Name) ?? email;
        var token = await authService.GetOrCreateUploadTokenAsync(email, ct);
        UploadToken = token ?? string.Empty;
        var publicBaseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        UploadIntakeUrlPrefix = $"{publicBaseUrl}/u/";
        UploadIntakeUrl = string.IsNullOrWhiteSpace(token) ? string.Empty : $"{publicBaseUrl}/u/{Uri.EscapeDataString(token)}";
        ViewData["Title"] = "Account Settings";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }

    public async Task<IActionResult> OnPostChangeEmailAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var newEmail = (Request.Form["newEmail"].ToString() ?? string.Empty).Trim();
        var currentPassword = Request.Form["currentPasswordForEmail"].ToString();
        var publicBaseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        var confirmationUrlBase = $"{publicBaseUrl}/auth/confirm-email-change";

        var result = await authService.RequestEmailChangeAsync(email, newEmail, currentPassword, confirmationUrlBase, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Confirm your new email to complete the change" });
    }

    public async Task<IActionResult> OnPostUpdateProfileAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var displayName = Request.Form["displayName"].ToString();
        var result = await authService.SetDisplayNameAsync(email, displayName, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var role = User.FindFirstValue(ClaimTypes.Role) ?? "user";
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId),
            new(ClaimTypes.Email, email),
            new(ClaimTypes.Name, result.DisplayName ?? email),
            new(ClaimTypes.Role, role)
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

        return RedirectToPage("/Account/Settings", new { msg = "Profile updated" });
    }

    public async Task<IActionResult> OnPostChangePasswordAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var currentPassword = Request.Form["currentPasswordForPassword"].ToString();
        var newPassword = Request.Form["newPassword"].ToString();
        var confirmPassword = Request.Form["confirmPassword"].ToString();

        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            return RedirectToPage("/Account/Settings", new { msg = "New passwords do not match" });
        }

        var publicBaseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        var confirmationUrlBase = $"{publicBaseUrl}/auth/confirm-password-change";
        var result = await authService.RequestPasswordChangeAsync(email, currentPassword, newPassword, confirmationUrlBase, ct);
        return RedirectToPage("/Account/Settings", new { msg = result.Success ? "Check your email to confirm the password change" : result.Error });
    }

    public async Task<IActionResult> OnPostRegenerateUploadLinkAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var token = await authService.RegenerateUploadTokenAsync(email, ct);
        if (string.IsNullOrWhiteSpace(token))
        {
            return RedirectToPage("/Account/Settings", new { msg = "Unable to regenerate upload link" });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Upload link regenerated" });
    }

    public async Task<IActionResult> OnPostSetUploadLinkAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var requestedToken = Request.Form["uploadToken"].ToString();
        var result = await authService.SetUploadTokenAsync(email, requestedToken, ct);
        if (!result.Success)
        {
            return RedirectToPage("/Account/Settings", new { msg = result.Error });
        }

        return RedirectToPage("/Account/Settings", new { msg = "Upload link updated" });
    }

    private static string ResolvePublicBaseUrl(string? configuredValue, HttpRequest request)
    {
        var configured = (configuredValue ?? string.Empty).Trim().TrimEnd('/');
        if (configured.Length > 0 && Uri.TryCreate(configured, UriKind.Absolute, out var absolute))
        {
            return absolute.GetLeftPart(UriPartial.Authority);
        }

        return $"{request.Scheme}://{request.Host}";
    }
}
