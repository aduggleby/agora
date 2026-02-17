namespace Agora.Web.Pages.Shared;

public sealed record ShareLandingCardViewModel(
    string Title,
    string? Subtitle,
    string Description,
    string ZipDisplayName,
    int FileCount,
    string SizeDisplay,
    bool IsExpired,
    string DownloadUrl);
