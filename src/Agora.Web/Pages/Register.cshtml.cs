using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Agora.Web.Pages;

public class RegisterModel(AuthService authService, AgoraDbContext db) : PageModel
{
    public string Message { get; private set; } = string.Empty;
    public bool RegistrationAllowed { get; private set; }

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

        var userCount = await db.Users.CountAsync(ct);
        var allowRegistration = await authService.GetAllowRegistrationAsync(ct);
        RegistrationAllowed = userCount == 0 || allowRegistration;
        Message = Request.Query["msg"].ToString();
        ViewData["Title"] = "Register";
        ViewData["Message"] = Message;

        return Page();
    }
}
