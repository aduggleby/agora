using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Pages;

[EnableRateLimiting("AuthEndpoints")]
public class ResetPasswordModel(AuthService authService) : PageModel
{
    public bool CanSubmit { get; private set; }
    public string Email { get; private set; } = string.Empty;
    public string Token { get; private set; } = string.Empty;

    public IActionResult OnGet()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

        // The emailed link carries the token in the query string: do not pass it on in a Referer.
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Email = Request.Query["email"].ToString();
        Token = Request.Query["token"].ToString();
        CanSubmit = !string.IsNullOrWhiteSpace(Email) && !string.IsNullOrWhiteSpace(Token);
        ViewData["Title"] = "Reset Password";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        var email = Request.Form["email"].ToString();
        var token = Request.Form["token"].ToString();
        var newPassword = Request.Form["newPassword"].ToString();
        var confirmPassword = Request.Form["confirmPassword"].ToString();

        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            return RetryPage(email, token, "Passwords do not match");
        }

        var result = await authService.ResetPasswordAsync(email, token, newPassword, ct);
        if (!result.Success)
        {
            return RetryPage(email, token, result.Error);
        }

        return Redirect("/login?msg=Password%20updated.%20You%20can%20sign%20in");
    }

    // Re-render with the token in the hidden form field rather than round-tripping it through a redirect URL.
    private IActionResult RetryPage(string email, string token, string message)
    {
        Email = email;
        Token = token;
        CanSubmit = !string.IsNullOrWhiteSpace(Email) && !string.IsNullOrWhiteSpace(Token);
        ViewData["Title"] = "Reset Password";
        ViewData["Message"] = message;
        return Page();
    }
}
