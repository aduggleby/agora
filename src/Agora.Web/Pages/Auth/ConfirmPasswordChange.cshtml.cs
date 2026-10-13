using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages.Auth;

[EnableRateLimiting(RateLimitSetup.AuthEndpoints)]
public class ConfirmPasswordChangeModel(AuthService authService) : ConfirmActionPageModel
{
    public override string Heading => "Confirm password change";
    public override string Description => "Confirm the new password for the account below. You will be signed out afterwards.";
    public override string ButtonLabel => "Confirm password change";

    protected override async Task<IActionResult> ConfirmAsync(string email, string token, CancellationToken ct)
    {
        var result = await authService.ConfirmPasswordChangeAsync(email, token, ct);
        if (!result.Success)
        {
            // A failed or stale link must not end the visitor's session.
            return Redirect($"/login?msg={Uri.EscapeDataString(result.Error)}");
        }

        if (User.Identity?.IsAuthenticated == true)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        return Redirect("/login?msg=Password%20updated.%20Please%20sign%20in%20again");
    }
}
