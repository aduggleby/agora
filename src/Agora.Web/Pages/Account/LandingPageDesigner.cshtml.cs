using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Account;

[Authorize]
public class LandingPageDesignerModel(ShareManager manager) : PageModel
{
    public ShareTemplateData Template { get; private set; } = new("Shared file", "A file was shared with you", string.Empty, null, null, "center");

    public async Task OnGet(CancellationToken ct)
    {
        if (User.TryGetShareOwner(out var owner))
        {
            Template = await manager.GetAccountTemplateAsync(owner, ct);
        }

        ViewData["Title"] = "Download Page Settings";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
