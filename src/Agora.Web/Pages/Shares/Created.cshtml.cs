using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Pages.Shared;
using Agora.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Shares;

[Authorize]
public class CreatedModel(PublicBaseUrlResolver publicBaseUrls, ShareManager manager, ShareCreationStatusStore statusStore) : PageModel
{
    public string Token { get; private set; } = string.Empty;
    public string ShareUrl { get; private set; } = string.Empty;
    public ShareLandingCardViewModel? PreviewCard { get; private set; }
    public bool IsReady { get; private set; }
    public bool IsFailed { get; private set; }
    public string? StatusError { get; private set; }

    public async Task<IActionResult> OnGet()
    {
        var token = Request.Query["token"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Redirect("/");
        }

        Token = token;
        var baseUrl = publicBaseUrls.Resolve(Request);
        ShareUrl = $"{baseUrl}/s/{Uri.EscapeDataString(token)}";

        if (!User.TryGetShareOwner(out var owner))
        {
            return Redirect("/");
        }

        var share = await manager.FindByTokenAsync(token, HttpContext.RequestAborted);
        if (share is not null)
        {
            if (!owner.Owns(share.OwnerUserId))
            {
                return Redirect("/");
            }

            IsReady = true;
            var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
                ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
                : $"{share.ZipSizeBytes / 1024.0:F0} KB";
            var isExpired = ShareManager.IsExpired(share, DateTime.UtcNow);
            PreviewCard = new ShareLandingCardViewModel(
                Title: share.PageH1,
                Subtitle: share.PageTitle,
                Description: share.PageDescription,
                ZipDisplayName: share.ZipDisplayName,
                FileCount: share.Files.Count,
                SizeDisplay: sizeDisplay,
                IsExpired: isExpired,
                DownloadUrl: $"/s/{Uri.EscapeDataString(token)}/download",
                IsDownloadAllowed: ShareManager.AllowsZipDownload(share),
                DownloadDisabledReason: "ZIP download is disabled for this share mode.",
                RequiresPassword: !string.IsNullOrWhiteSpace(share.DownloadPasswordHash));
        }
        else
        {
            var status = statusStore.Read(token);
            if (status is null || status.OwnerUserId != owner.UserId)
            {
                return Redirect("/");
            }

            if (string.Equals(status.State, "failed", StringComparison.OrdinalIgnoreCase))
            {
                IsFailed = true;
                StatusError = status.Error;
            }
        }

        ViewData["Title"] = "Share created";
        return Page();
    }
}
