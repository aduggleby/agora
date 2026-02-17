using System.Security.Claims;
using Agora.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages;

[Authorize]
public class IndexModel(ShareManager manager) : PageModel
{
    public List<ShareManager.UserShareSummary> Shares { get; private set; } = [];
    public bool IsAdmin { get; private set; }
    public string QuickDraftShareId { get; private set; } = string.Empty;

    public async Task OnGet(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        IsAdmin = User.IsInRole("admin");
        Shares = (await manager.ListRecentSharesForUploaderAsync(email, 20, ct))
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToList();
        QuickDraftShareId = await manager.EnsureDraftShareAsync(email, null, ct);

        ViewData["Title"] = "Agora";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
