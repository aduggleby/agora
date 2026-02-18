namespace Agora.Domain.Entities;

public sealed class Share
{
    public Guid Id { get; set; }
    public string UploaderEmail { get; set; } = string.Empty;
    public string ShareToken { get; set; } = string.Empty;
    public string ShareTokenHash { get; set; } = string.Empty;
    public string ShareTokenPrefix { get; set; } = string.Empty;
    public string ZipDisplayName { get; set; } = string.Empty;
    public string ZipDiskPath { get; set; } = string.Empty;
    public long ZipSizeBytes { get; set; }
    public string ShareExperienceType { get; set; } = "archive";
    public string AccessMode { get; set; } = "download_only";
    public string? ContentRootPath { get; set; }
    public string? DownloadPasswordHash { get; set; }
    public string? UploaderMessage { get; set; }
    public string NotifyMode { get; set; } = "none";
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime? FirstDownloadedAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? DeletedAtUtc { get; set; }

    public string PageTitle { get; set; } = "Shared file";
    public string PageH1 { get; set; } = "A file was shared with you";
    public string PageDescription { get; set; } = "Use the button below to download your file.";
    public string? BackgroundImageUrl { get; set; }
    public string? PageBackgroundColorHex { get; set; }
    public string PageContainerPosition { get; set; } = "center";

    public ICollection<ShareFile> Files { get; set; } = new List<ShareFile>();
    public ICollection<DownloadEvent> DownloadEvents { get; set; } = new List<DownloadEvent>();
}
