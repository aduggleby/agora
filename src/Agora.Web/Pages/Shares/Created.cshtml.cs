using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Pages.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Agora.Web.Pages.Shares;

[Authorize]
public class CreatedModel(IOptions<AgoraOptions> options, ShareManager manager) : PageModel
{
    public string Token { get; private set; } = string.Empty;
    public string ShareUrl { get; private set; } = string.Empty;
    public ShareLandingCardViewModel? PreviewCard { get; private set; }

    public async Task<IActionResult> OnGet()
    {
        var token = Request.Query["token"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return Redirect("/shares/new?msg=Missing%20share%20token");
        }

        Token = token;
        var baseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        ShareUrl = $"{baseUrl}/s/{Uri.EscapeDataString(token)}";

        var share = await manager.FindByTokenAsync(token, HttpContext.RequestAborted);
        if (share is not null)
        {
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
                DownloadUrl: $"/s/{Uri.EscapeDataString(token)}/download");
        }

        ViewData["Title"] = "Share created";
        return Page();
    }

    private static string ResolvePublicBaseUrl(string? configuredValue, HttpRequest request)
    {
        var configured = (configuredValue ?? string.Empty).Trim().TrimEnd('/');
        if (configured.Length > 0 && Uri.TryCreate(configured, UriKind.Absolute, out var absolute))
        {
            return absolute.GetLeftPart(UriPartial.Authority);
        }

        return $"{request.Scheme}://{request.Host}";
    }
}
