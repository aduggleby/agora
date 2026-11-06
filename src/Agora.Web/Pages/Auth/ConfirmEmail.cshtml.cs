using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages.Auth;

[EnableRateLimiting(RateLimitSetup.AuthEndpoints)]
public class ConfirmEmailModel(AuthService authService) : ConfirmActionPageModel
{
    public override string Heading => "Confirm your email";
    public override string Description => "Enter the password you chose when registering to activate your account.";
    public override string ButtonLabel => "Confirm email";
    public override bool RequiresPassword => true;

    protected override async Task<IActionResult> ConfirmAsync(string email, string token, CancellationToken ct)
    {
        var password = Request.Form["password"].ToString();
        if (string.IsNullOrEmpty(password))
        {
            return ShowFormWithError(email, token, "Enter your password.");
        }

        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        (bool Success, string Error) result;
        try
        {
            result = await authService.ConfirmEmailAsync(email, token, password, clientIp, ct);
        }
        catch (PasswordHashingBusyException)
        {
            // Keep the link on screen: the token was not used.
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            Response.Headers.RetryAfter = PasswordHashingBusyException.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return ShowFormWithError(email, token, PasswordHashingBusyException.BusyMessage);
        }

        if (result.Success)
        {
            return Redirect("/login?msg=Email%20confirmed.%20You%20can%20now%20sign%20in");
        }

        return string.Equals(result.Error, AuthService.ConfirmationPasswordError, StringComparison.Ordinal)
            ? ShowFormWithError(email, token, result.Error)
            : Redirect($"/login?msg={Uri.EscapeDataString(result.Error)}");
    }
}
