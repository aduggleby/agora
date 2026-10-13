using Agora.Infrastructure.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages;

[EnableRateLimiting("AuthEndpoints")]
public class ForgotPasswordModel(AuthService authService, PublicBaseUrlResolver publicBaseUrls) : PageModel
{
    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

        ViewData["Title"] = "Forgot Password";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var email = Request.Form["email"].ToString();
        var resetUrlBase = $"{publicBaseUrls.Resolve(Request)}/reset-password";
        await authService.RequestPasswordResetAsync(email, resetUrlBase, ct);
        return RedirectToPage("/ForgotPassword", new { msg = "If the account exists, a reset email was sent" });
    }
}
