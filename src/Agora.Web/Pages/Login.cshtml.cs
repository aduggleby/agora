using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Agora.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Agora.Web.Pages;

public class LoginModel(AuthService authService, AgoraDbContext db, IWebHostEnvironment env) : PageModel
{
    public string Message { get; private set; } = string.Empty;
    public bool ShowRegister { get; private set; }
    public bool ShowDevelopmentLogin { get; private set; }
    /// <summary>The local path to return to after sign-in (for example an app's consent page), or null.</summary>
    public string? ReturnUrl { get; private set; }

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        // Signed in already: always home. Honoring returnUrl here would loop, because access denied redirects here too.
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

        var returnUrl = Request.Query[AuthSetup.ReturnUrlParameter].ToString();
        ReturnUrl = LocalUrls.IsLocal(returnUrl) ? returnUrl : null;

        var userCount = await db.Users.CountAsync(ct);
        var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
        ShowRegister = userCount == 0 || allowRegistration;
        ShowDevelopmentLogin = env.IsDevelopment();
        Message = Request.Query["msg"].ToString();
        ViewData["Title"] = "Sign in";
        ViewData["Message"] = Message;
        return Page();
    }
}
