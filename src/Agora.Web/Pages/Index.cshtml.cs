using System.Security.Claims;
using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages;

[Authorize]
public class IndexModel(ShareManager manager, IOptions<AgoraOptions> options) : PageModel
{
    private readonly AgoraOptions _options = options.Value;

    public List<ShareManager.UserShareSummary> OwnShares { get; private set; } = [];
    public List<ShareManager.UserShareSummary> ReceivedShares { get; private set; } = [];
    public bool IsAdmin { get; private set; }
    public string QuickDraftShareId { get; private set; } = string.Empty;
    public long MaxFileSizeBytes => _options.MaxFileSizeBytes;
    public long MaxTotalUploadBytes => _options.MaxTotalUploadBytes;
    public int MaxFilesPerShare => _options.MaxFilesPerShare;

    public async Task OnGet(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        IsAdmin = User.IsInRole("admin");
        var shares = (await manager.ListRecentSharesForUploaderAsync(email, 100, ct))
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToList();
        ReceivedShares = shares
            .Where(x => !string.IsNullOrWhiteSpace(x.SenderEmail))
            .ToList();
        OwnShares = shares
            .Where(x => string.IsNullOrWhiteSpace(x.SenderEmail))
            .ToList();
        QuickDraftShareId = await manager.EnsureDraftShareAsync(email, null, ct);

        ViewData["Title"] = "Agora";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
