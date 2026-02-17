using System.Security.Claims;
using Agora.Infrastructure.Services;
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
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var requestedDraftShareId = Request.Query["draftShareId"].ToString();
        try
        {
            DraftShareId = await manager.EnsureDraftShareAsync(email, requestedDraftShareId, ct);
        }
        catch
        {
            return Redirect("/shares/new?msg=Unable%20to%20open%20share%20designer");
        }

        DraftTemplate = await manager.GetDraftTemplateAsync(email, DraftShareId, ct);
        ViewData["Title"] = "Share Download Page Designer";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }
}
