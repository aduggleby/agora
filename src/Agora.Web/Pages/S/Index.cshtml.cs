using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Agora.Web.Pages.S;

public class IndexModel(ShareManager manager, ShareExperienceRendererResolver shareExperienceRendererResolver, IOptions<AgoraOptions> agoraOptions, ILogger<IndexModel> logger) : PageModel
{
    public sealed record PreviewItemViewModel(
        Guid Id,
        string OriginalFilename,
        string SizeDisplay,
        string PreviewKind,
        string RenderType,
        string PreviewImageUrl,
        string PreviewStatusUrl,
        string RetryPreviewUrl,
        string FileUrl,
        string DownloadUrl,
        string ThumbnailUrl,
        string ExtensionLabel);

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
    public string DisplayH1 { get; private set; } = "File Download";
    public bool AllowsPreview { get; private set; }
    public bool AllowsZipDownload { get; private set; }
    public IReadOnlyList<PreviewItemViewModel> PreviewItems { get; private set; } = [];
    public PreviewItemViewModel? InitialPreviewItem { get; private set; }
    public bool HasPreviewExperience => !IsExpired && AllowsPreview && PreviewItems.Count > 0;
    public bool IsSingleFilePreview => HasPreviewExperience && PreviewItems.Count == 1;
    public bool IsImageMosaicPreview => HasPreviewExperience && PreviewItems.Count > 1 && PreviewItems.All(x => x.PreviewKind == "image");
    public bool IsMixedFilePreview => HasPreviewExperience && !IsSingleFilePreview && !IsImageMosaicPreview;

    public async Task<IActionResult> OnGet(string token, CancellationToken ct)
    {
        Token = token;
        Share = await manager.FindByTokenAsync(token, ct);
        if (Share is null)
        {
            return NotFound("Share not found.");
        }

        IsExpired = ShareManager.IsExpired(Share, DateTime.UtcNow);
        DisplayH1 = ResolveDisplayH1(Share.PageH1, Share.Files.Count);
        RequiresPassword = !string.IsNullOrWhiteSpace(Share.DownloadPasswordHash);
        var presentation = shareExperienceRendererResolver.Resolve(Share);
        AllowsPreview = presentation.AllowsPreview && !RequiresPassword;
        AllowsZipDownload = presentation.AllowsZipDownload;
        PreviewItems = presentation.PreviewFiles
            .OrderBy(file => file.OriginalFilename, StringComparer.OrdinalIgnoreCase)
            .Select(file => new PreviewItemViewModel(
                file.Id,
                file.OriginalFilename,
                FormatSize(file.OriginalSizeBytes),
                ResolvePreviewKind(file.RenderType),
                file.RenderType,
                $"/s/{token}/files/{file.Id}/preview?width=960&height=720",
                $"/s/{token}/files/{file.Id}/preview-status",
                $"/s/{token}/files/{file.Id}/preview/retry",
                $"/s/{token}/files/{file.Id}",
                $"/s/{token}/files/{file.Id}?download=1",
                $"/s/{token}/files/{file.Id}/thumbnail?width=420&height=300",
                ResolveExtensionLabel(file.OriginalFilename)))
            .ToList();
        InitialPreviewItem = PreviewItems.FirstOrDefault();
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
        SizeDisplay = FormatSize(Share.ZipSizeBytes);
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

    private static string ResolveDisplayH1(string? rawH1, int fileCount)
    {
        var h1 = string.IsNullOrWhiteSpace(rawH1) ? "File Download" : rawH1;
        if (fileCount > 1 && string.Equals(h1.Trim(), "A file was shared with you", StringComparison.OrdinalIgnoreCase))
        {
            return $"{fileCount} files were shared with you";
        }

        return h1;
    }

    private static string ResolvePreviewKind(string? renderType)
    {
        var value = (renderType ?? string.Empty).Trim().ToLowerInvariant();
        return value switch
        {
            "image" => "image",
            "video" => "video",
            "audio" => "audio",
            "pdf" => "pdf",
            "text" => "text",
            _ => "generic"
        };
    }

    private static string ResolveExtensionLabel(string? fileName)
    {
        var ext = Path.GetExtension(fileName ?? string.Empty).Trim().TrimStart('.').ToUpperInvariant();
        return ext.Length == 0 ? "FILE" : ext;
    }

    private static string FormatSize(long sizeBytes)
    {
        const long OneMb = 1024L * 1024L;
        const long OneGb = 1024L * 1024L * 1024L;
        const long GbSwitchThreshold = 1000L * OneMb;

        if (sizeBytes >= GbSwitchThreshold)
        {
            return $"{sizeBytes / (double)OneGb:F1} GB";
        }

        if (sizeBytes >= 1024L * 1024L)
        {
            return $"{sizeBytes / (1024.0 * 1024.0):F1} MB";
        }

        if (sizeBytes >= 1024L)
        {
            return $"{sizeBytes / 1024.0:F0} KB";
        }

        return $"{sizeBytes} B";
    }
}
