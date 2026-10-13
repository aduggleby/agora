using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
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
        IsAdmin = User.IsInRole("admin");
        var shares = User.TryGetShareOwner(out var owner)
            ? await manager.ListRecentSharesForUploaderAsync(owner, 100, ct)
            : [];
        shares = shares
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToList();
        ReceivedShares = shares
            .Where(x => !string.IsNullOrWhiteSpace(x.SenderEmail))
            .ToList();
        OwnShares = shares
            .Where(x => string.IsNullOrWhiteSpace(x.SenderEmail))
            .ToList();
        QuickDraftShareId = User.UserId() is { } userId ? await manager.EnsureDraftShareAsync(userId, null, ct) : string.Empty;

        ViewData["Title"] = "Agora";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
