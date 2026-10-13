using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Services;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.S;

public class IndexModel(ShareManager manager, IObjectStore objectStore, ShareExperienceRendererResolver shareExperienceRendererResolver, PublicBaseUrlResolver publicBaseUrls, ILogger<IndexModel> logger) : PageModel
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
        // The token is the share's access key: never let it leave in a Referer when the page links out.
        Response.Headers["Referrer-Policy"] = "same-origin";
        Token = token;
        Share = await manager.FindByTokenAsync(token, ct);
        if (Share is not null && ShareModes.IsDirectLink(Share.AccessMode) && ShareManager.IsDeleted(Share))
        {
            // A direct link that was deleted early or purged by cleanup is gone like an expired one: the recipient
            // (or an embed) gets the expired page with 410, never a 404 that would read as a wrong link.
            IsExpired = true;
        }
        else if (Share is null || ShareManager.IsDeleted(Share))
        {
            // Deleted shares are indistinguishable from unknown tokens; nothing of them is rendered.
            return NotFound("Share not found.");
        }

        IsExpired = IsExpired || ShareManager.IsExpired(Share, DateTime.UtcNow);
        if (IsExpired)
        {
            // The expired view is still rendered, but crawlers and clients see the share is gone.
            Response.StatusCode = StatusCodes.Status410Gone;
        }

        if (ShareModes.IsDirectLink(Share.AccessMode) && !IsExpired)
        {
            // A live direct link is the file itself; an expired one falls through to the expired view (410).
            return await ServeDirectLinkAsync(Share, token, ct);
        }

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
                $"/s/{token}/files/{file.Id}/preview",
                $"/s/{token}/files/{file.Id}/preview-status",
                $"/s/{token}/files/{file.Id}/preview/retry",
                $"/s/{token}/files/{file.Id}",
                $"/s/{token}/files/{file.Id}?download=1",
                $"/s/{token}/files/{file.Id}/thumbnail",
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
        logger.LogDebug(
            "Download page load for share {TokenRef}: marker {BackgroundMarker}, background {BackgroundKind}",
            LogSafe.Token(token),
            string.IsNullOrWhiteSpace(Share.BackgroundImageUrl) ? "<empty>" : Share.BackgroundImageUrl,
            string.IsNullOrWhiteSpace(BackgroundImageUrl) ? "none" : BackgroundImageUrl.StartsWith("/s/", StringComparison.Ordinal) ? "internal" : "external");
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

        // OG tags are read by crawlers, so they use the configured public origin, never the request host.
        var publicBase = publicBaseUrls.Resolve(Request);
        OgImageUrl = $"{publicBase}/s/{token}/og-image";
        PageUrl = $"{publicBase}/s/{token}";

        ViewData["Title"] = "File Download";
        return Page();
    }

    /// <summary>
    /// Streams the single file of a direct link under the user-content policy (extension-derived type, nosniff,
    /// sandbox CSP). Every request counts as a download, whoever makes it; direct links never notify.
    /// </summary>
    private async Task<IActionResult> ServeDirectLinkAsync(Domain.Entities.Share share, string token, CancellationToken ct)
    {
        var file = share.Files.SingleOrDefault();
        var stored = file is not null && ObjectKey.TryNormalize(file.StoredRelativePath, out var key)
            ? await objectStore.OpenReadAsync(key, ct)
            : null;
        if (file is null || stored is null)
        {
            return StatusCode(StatusCodes.Status410Gone);
        }

        try
        {
            var remote = HttpContext.Connection.RemoteIpAddress?.ToString();
            var ip = IpAddressUtilities.TryNormalizeIp(remote, out var normalized) ? normalized : "unknown";
            await manager.RecordDownloadAsync(share, token, ip, Request.Headers.UserAgent.ToString(), ct);
        }
        catch
        {
            await stored.Content.DisposeAsync();
            throw;
        }

        await ObjectResults.UserContent(Response, stored, file.OriginalFilename).ExecuteAsync(HttpContext);
        return new EmptyResult();
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
            return $"{sizeBytes / (double)OneGb:0.#} GB";
        }

        if (sizeBytes >= 1024L * 1024L)
        {
            return $"{sizeBytes / (1024.0 * 1024.0):0.#} MB";
        }

        if (sizeBytes >= 1024L)
        {
            return $"{sizeBytes / 1024.0:F0} KB";
        }

        return $"{sizeBytes} B";
    }
}
