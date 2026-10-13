using Agora.Application.Utilities;
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
        // Read the route value directly: a bound handler parameter would also accept ?token= and hide the
        // compatibility redirect below.
        var token = RouteData.Values["token"]?.ToString();
        // The token is a route segment, never a query string, and the page's outbound links send no path.
        Response.Headers["Referrer-Policy"] = "same-origin";
        if (!User.TryGetShareOwner(out var owner))
        {
            return Redirect("/");
        }

        // Lenient shape check only: tokens created before the current format rules (shorter, non-ASCII letters)
        // must still open here; ownership is enforced below.
        var fromRoute = !string.IsNullOrWhiteSpace(token);
        token = (fromRoute ? token! : Request.Query["token"].ToString()).Trim();
        if (token.Length is 0 or > ShareTokens.MaxLength || token.Any(char.IsControl))
        {
            return NotFound();
        }

        var share = await manager.FindByTokenAsync(token, HttpContext.RequestAborted);
        if (!fromRoute)
        {
            // Compatibility with links that still carry ?token= (browser history, older emails): the owner is sent to
            // the route form; anyone else learns nothing.
            var owned = share is not null
                ? owner.Owns(share.OwnerUserId)
                : statusStore.Read(token)?.OwnerUserId == owner.UserId;
            return owned ? Redirect($"/shares/created/{Uri.EscapeDataString(token)}") : NotFound();
        }

        Token = token;
        var baseUrl = publicBaseUrls.Resolve(Request);
        ShareUrl = $"{baseUrl}/s/{Uri.EscapeDataString(token)}";

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
            var isExpired = !ShareManager.IsActive(share, DateTime.UtcNow);
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
