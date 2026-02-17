using Agora.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.S;

public class IndexModel(ShareManager manager, ILogger<IndexModel> logger) : PageModel
{
    public Domain.Entities.Share? Share { get; private set; }
    public string Token { get; private set; } = string.Empty;
    public bool IsExpired { get; private set; }
    public string BackgroundImageUrl { get; private set; } = string.Empty;
    public string SizeDisplay { get; private set; } = "0 KB";
    public string ContainerAlignItems { get; private set; } = "center";
    public string ContainerJustifyContent { get; private set; } = "center";

    public async Task<IActionResult> OnGet(string token, CancellationToken ct)
    {
        Token = token;
        Share = await manager.FindByTokenAsync(token, ct);
        if (Share is null)
        {
            return NotFound("Share not found.");
        }

        IsExpired = ShareManager.IsExpired(Share, DateTime.UtcNow);
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

        ViewData["Title"] = "File Download";
        return Page();
    }
}
