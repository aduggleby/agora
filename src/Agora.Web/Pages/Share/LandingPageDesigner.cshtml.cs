using System.Security.Claims;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Share;

[Authorize]
public class LandingPageDesignerModel(ShareManager manager) : PageModel
{
    public string DraftShareId { get; private set; } = string.Empty;
    public ShareManager.DraftTemplateState DraftTemplate { get; private set; } = new("", "account_default", "", "", "", null, null, null, "center");

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return Redirect("/login");
        }

        var requestedDraftShareId = Request.Query["draftShareId"].ToString();
        try
        {
            DraftShareId = await manager.EnsureDraftShareAsync(userId, requestedDraftShareId, ct);
        }
        catch
        {
            return Redirect("/shares/new?msg=Unable%20to%20open%20share%20designer");
        }

        DraftTemplate = await manager.GetDraftTemplateAsync(userId, DraftShareId, ct);
        ViewData["Title"] = "Share Download Page Designer";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }
}
