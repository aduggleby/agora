using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Agora.Web.Pages.S;

public class IndexModel(ShareManager manager, ShareExperienceRendererResolver shareExperienceRendererResolver, IOptions<AgoraOptions> agoraOptions, ILogger<IndexModel> logger) : PageModel
{
    public Domain.Entities.Share? Share { get; private set; }
    public string Token { get; private set; } = string.Empty;
    public bool IsExpired { get; private set; }
    public string BackgroundImageUrl { get; private set; } = string.Empty;
    public string SizeDisplay { get; private set; } = "0 KB";
    public string ContainerAlignItems { get; private set; } = "center";
    public string ContainerJustifyContent { get; private set; } = "center";
    public string OgImageUrl { get; private set; } = string.Empty;
    public string PageUrl { get; private set; } = string.Empty;
    public string? DownloadError { get; private set; }
    public bool RequiresPassword { get; private set; }
    public string ShareExperienceType { get; private set; } = "archive";
    public string AccessMode { get; private set; } = "download_only";
    public bool AllowsPreview { get; private set; }
    public bool AllowsZipDownload { get; private set; }
    public IReadOnlyList<Domain.Entities.ShareFile> PreviewFiles { get; private set; } = [];
    public IReadOnlyList<Domain.Entities.ShareFile> GalleryFiles { get; private set; } = [];

    public async Task<IActionResult> OnGet(string token, CancellationToken ct)
    {
        Token = token;
        Share = await manager.FindByTokenAsync(token, ct);
        if (Share is null)
        {
            return NotFound("Share not found.");
        }

        IsExpired = ShareManager.IsExpired(Share, DateTime.UtcNow);
        var presentation = shareExperienceRendererResolver.Resolve(Share);
        ShareExperienceType = presentation.ExperienceType;
        AccessMode = ShareManager.NormalizeAccessMode(Share.AccessMode);
        AllowsPreview = presentation.AllowsPreview;
        AllowsZipDownload = presentation.AllowsZipDownload;
        PreviewFiles = presentation.PreviewFiles;
        GalleryFiles = presentation.GalleryFiles;
        RequiresPassword = !string.IsNullOrWhiteSpace(Share.DownloadPasswordHash);
        DownloadError = (Request.Query["downloadError"].ToString().Trim().ToLowerInvariant()) switch
        {
            "password_required" => "Enter the password to download this file.",
            "invalid_password" => "Password was incorrect or the encrypted file could not be unlocked.",
            "download_disabled" => "ZIP download is disabled for this share mode.",
            _ => null
        };
        BackgroundImageUrl = string.IsNullOrWhiteSpace(Share.BackgroundImageUrl)
            ? string.Empty
            : Share.BackgroundImageUrl.StartsWith("internal:", StringComparison.OrdinalIgnoreCase)
                ? $"/s/{token}/background"
                : Share.BackgroundImageUrl;
        logger.LogInformation(
            "Download page load for token {Token}: marker {BackgroundMarker}, resolved background URL {BackgroundUrl}",
            token,
            string.IsNullOrWhiteSpace(Share.BackgroundImageUrl) ? "<empty>" : Share.BackgroundImageUrl,
            string.IsNullOrWhiteSpace(BackgroundImageUrl) ? "<none>" : BackgroundImageUrl);
        SizeDisplay = Share.ZipSizeBytes >= 1024 * 1024
            ? $"{Share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
            : $"{Share.ZipSizeBytes / 1024.0:F0} KB";
        var containerPosition = ShareManager.NormalizeContainerPosition(Share.PageContainerPosition);
        (ContainerAlignItems, ContainerJustifyContent) = containerPosition switch
        {
            "top_left" => ("flex-start", "flex-start"),
            "top_right" => ("flex-end", "flex-start"),
            "bottom_left" => ("flex-start", "flex-end"),
            "bottom_right" => ("flex-end", "flex-end"),
            "center_right" => ("flex-end", "center"),
            "center_left" => ("flex-start", "center"),
            "center_top" => ("center", "flex-start"),
            "center_bottom" => ("center", "flex-end"),
            _ => ("center", "center")
        };

        // Resolve public base URL for OG tags
        var publicBase = agoraOptions.Value.PublicBaseUrl;
        if (string.IsNullOrWhiteSpace(publicBase))
        {
            publicBase = $"{Request.Scheme}://{Request.Host}";
        }
        publicBase = publicBase.TrimEnd('/');
        OgImageUrl = $"{publicBase}/s/{token}/og-image";
        PageUrl = $"{publicBase}/s/{token}";

        ViewData["Title"] = "File Download";
        return Page();
    }
}
