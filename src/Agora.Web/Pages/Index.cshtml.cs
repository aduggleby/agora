using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages;

[Authorize]
public class IndexModel(ShareManager manager, AuthService authService, PublicBaseUrlResolver publicBaseUrls, IOptions<AgoraOptions> options) : PageModel
{
    private readonly AgoraOptions _options = options.Value;

    /// <summary>The owner's own shares, newest first (the 100 newest).</summary>
    public List<ShareManager.UserShareSummary> OwnShares { get; private set; } = [];
    /// <summary>Files people sent through the owner's upload link, newest first (the 100 newest).</summary>
    public List<ShareManager.UserShareSummary> ReceivedShares { get; private set; } = [];
    /// <summary>When the Received tab was last opened before this page view; null means never.</summary>
    public DateTime? ReceivedSeenAtUtc { get; private set; }
    /// <summary>
    /// Creation time of the newest received share this page shows; opening the Received tab marks everything up to it as
    /// seen. Not the render time: a share's CreatedAtUtc is set before its archive is built, so one that was still being
    /// created while this page was rendered can carry an older timestamp and must stay new.
    /// </summary>
    public DateTime? SeenUpToUtc { get; private set; }
    public int NewReceivedCount { get; private set; }
    public string UploadIntakeUrl { get; private set; } = string.Empty;
    public string ActiveTab { get; private set; } = "mine";
    public bool IsAdmin { get; private set; }
    public string QuickDraftShareId { get; private set; } = string.Empty;
    public long MaxFileSizeBytes => _options.MaxFileSizeBytes;
    public long MaxTotalUploadBytes => _options.MaxTotalUploadBytes;
    public int MaxFilesPerShare => _options.MaxFilesPerShare;

    public bool IsNew(ShareManager.UserShareSummary share) => ShareManager.IsNewReceived(share.CreatedAtUtc, ReceivedSeenAtUtc);

    public async Task OnGet(CancellationToken ct)
    {
        IsAdmin = User.IsInRole("admin");
        if (User.TryGetShareOwner(out var owner))
        {
            OwnShares = await manager.ListOwnSharesAsync(owner, ShareManager.HomeListSize, ct);
            ReceivedShares = await manager.ListReceivedSharesAsync(owner, ShareManager.HomeListSize, ct);
            ReceivedSeenAtUtc = await manager.GetReceivedSeenAtUtcAsync(owner.UserId, ct);
            NewReceivedCount = ReceivedShares.Count(IsNew);
            SeenUpToUtc = ReceivedShares.Count == 0 ? null : DateTime.SpecifyKind(ReceivedShares.Max(x => x.CreatedAtUtc), DateTimeKind.Utc);
            var token = await authService.GetOrCreateUploadTokenAsync(owner.UserId, ct);
            UploadIntakeUrl = string.IsNullOrWhiteSpace(token) ? string.Empty : $"{publicBaseUrls.Resolve(Request)}/u/{Uri.EscapeDataString(token)}";
        }

        ActiveTab = string.Equals(Request.Query["tab"].ToString(), "received", StringComparison.Ordinal) ? "received" : "mine";
        QuickDraftShareId = User.UserId() is { } userId ? await manager.EnsureDraftShareAsync(userId, null, ct) : string.Empty;

        ViewData["Title"] = "Agora";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }
}
