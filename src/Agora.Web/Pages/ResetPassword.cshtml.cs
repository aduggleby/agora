using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages;

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

        Email = Request.Query["email"].ToString();
        Token = Request.Query["token"].ToString();
        CanSubmit = !string.IsNullOrWhiteSpace(Email) && !string.IsNullOrWhiteSpace(Token);
        ViewData["Title"] = "Reset Password";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var email = Request.Form["email"].ToString();
        var token = Request.Form["token"].ToString();
        var newPassword = Request.Form["newPassword"].ToString();
        var confirmPassword = Request.Form["confirmPassword"].ToString();

        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            return RedirectToPage("/ResetPassword", new { email, token, msg = "Passwords do not match" });
        }

        var result = await authService.ResetPasswordAsync(email, token, newPassword, ct);
        if (!result.Success)
        {
            return RedirectToPage("/ResetPassword", new { email, token, msg = result.Error });
        }

        return Redirect("/login?msg=Password%20updated.%20You%20can%20sign%20in");
    }
}
