using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Agora.Application.Models;

namespace Agora.Web.Pages;

public class ForgotPasswordModel(AuthService authService, IOptions<AgoraOptions> options) : PageModel
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
        var publicBaseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        var resetUrlBase = $"{publicBaseUrl}/reset-password";
        await authService.RequestPasswordResetAsync(email, resetUrlBase, ct);
        return RedirectToPage("/ForgotPassword", new { msg = "If the account exists, a reset email was sent" });
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
