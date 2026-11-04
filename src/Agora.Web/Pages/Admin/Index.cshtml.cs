using System.Security.Claims;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Authorization;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Admin;

[Authorize(Policy = AuthSetup.AdminOnlyPolicy)]
public class IndexModel(AuthService authService) : PageModel
{
    public IReadOnlyList<UserAccount> Users { get; private set; } = [];
    public bool AllowRegistration { get; private set; }
    public string CurrentUserEmail { get; private set; } = string.Empty;
    public string CurrentUserId { get; private set; } = string.Empty;

    public async Task OnGet(CancellationToken ct)
    {
        CurrentUserEmail = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        CurrentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        Users = await authService.GetUsersAsync(ct);
        AllowRegistration = await authService.GetAllowRegistrationAsync(ct);
        ViewData["Title"] = "Manage users";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
