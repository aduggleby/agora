using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Received;

[Authorize]
public class HistoryModel(ShareManager manager) : PageModel
{
    public const int PageSize = 50;

    public List<ShareManager.UserShareSummary> Shares { get; private set; } = [];
    public int PageNumber { get; private set; } = 1;
    public bool HasNext { get; private set; }

    public async Task OnGet(CancellationToken ct)
    {
        PageNumber = int.TryParse(Request.Query["page"], out var page) && page > 1 ? Math.Min(page, 100_000) : 1;
        if (User.TryGetShareOwner(out var owner))
        {
            // One extra row tells whether a next page exists.
            var rows = await manager.ListReceivedHistoryAsync(owner, (PageNumber - 1) * PageSize, PageSize + 1, ct);
            HasNext = rows.Count > PageSize;
            Shares = rows.Take(PageSize).ToList();
        }

        ViewData["Title"] = "Received history";
    }
}
