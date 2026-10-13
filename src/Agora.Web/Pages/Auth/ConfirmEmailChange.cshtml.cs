using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages.Auth;

[EnableRateLimiting(RateLimitSetup.AuthEndpoints)]
public class ConfirmEmailChangeModel(AuthService authService) : ConfirmActionPageModel
{
    public override string Heading => "Confirm new email";
    public override string Description => "Confirm that this address becomes the sign-in email for your account. You will be signed out afterwards.";
    public override string ButtonLabel => "Confirm email change";

    protected override async Task<IActionResult> ConfirmAsync(string email, string token, CancellationToken ct)
    {
        var result = await authService.ConfirmEmailChangeAsync(email, token, ct);
        if (!result.Success)
        {
            return Redirect($"/account/settings?msg={Uri.EscapeDataString(result.Error)}");
        }

        if (User.Identity?.IsAuthenticated == true)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        return Redirect("/login?msg=Email%20updated.%20Please%20sign%20in%20again");
    }
}
