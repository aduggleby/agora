using Agora.Infrastructure.Auth;
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

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

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
