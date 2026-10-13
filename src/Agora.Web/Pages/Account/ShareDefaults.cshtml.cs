using System.Security.Claims;
using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Account;

[Authorize]
public class ShareDefaultsModel(AuthService authService) : PageModel
{
    public string DefaultNotifyMode { get; private set; } = "once";
    public string DefaultExpiryMode { get; private set; } = "7_days";

    public async Task OnGet(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        DefaultNotifyMode = await authService.GetDefaultNotifyModeAsync(email, ct);
        DefaultExpiryMode = await authService.GetDefaultExpiryModeAsync(email, ct);
        ViewData["Title"] = "Share Defaults";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var defaultNotifyMode = (Request.Form["defaultNotifyMode"].ToString() ?? string.Empty).Trim();
        var defaultExpiryMode = (Request.Form["defaultExpiryMode"].ToString() ?? string.Empty).Trim();

        var notifyOk = await authService.SetDefaultNotifyModeAsync(email, defaultNotifyMode, ct);
        var expiryOk = await authService.SetDefaultExpiryModeAsync(email, defaultExpiryMode, ct);
        var ok = notifyOk && expiryOk;
        return RedirectToPage("/Account/ShareDefaults", new { msg = ok ? "Share defaults saved" : "Unable to save share defaults" });
    }
}
