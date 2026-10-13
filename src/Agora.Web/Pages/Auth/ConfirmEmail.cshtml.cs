using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages.Auth;

[EnableRateLimiting(RateLimitSetup.AuthEndpoints)]
public class ConfirmEmailModel(AuthService authService) : ConfirmActionPageModel
{
    public override string Heading => "Confirm your email";
    public override string Description => "Confirm the address below to activate your account.";
    public override string ButtonLabel => "Confirm email";

    protected override async Task<IActionResult> ConfirmAsync(string email, string token, CancellationToken ct)
    {
        var result = await authService.ConfirmEmailAsync(email, token, ct);
        return Redirect(result.Success
            ? "/login?msg=Email%20confirmed.%20You%20can%20now%20sign%20in"
            : $"/login?msg={Uri.EscapeDataString(result.Error)}");
    }
}
