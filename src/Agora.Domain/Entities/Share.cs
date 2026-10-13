namespace Agora.Domain.Entities;

/// <summary>
/// Persists a single public share, including access token, archive metadata, download policy, and page customization state.
/// </summary>
public sealed class Share
{
    public Guid Id { get; set; }
    public string UploaderEmail { get; set; } = string.Empty;
    /// <summary>
    /// Public URL token used to resolve the share at <c>/s/{token}</c>.
    /// </summary>
    public string ShareToken { get; set; } = string.Empty;
    public string ZipDisplayName { get; set; } = string.Empty;
    public string ZipDiskPath { get; set; } = string.Empty;
    public long ZipSizeBytes { get; set; }
    public string ShareExperienceType { get; set; } = "archive";
    public string AccessMode { get; set; } = "download_only";
    public string? ContentRootPath { get; set; }
    /// <summary>
    /// Hashed download password; raw password is never persisted.
    /// </summary>
    public string? DownloadPasswordHash { get; set; }
    public string? UploaderMessage { get; set; }
    public string? SenderName { get; set; }
    public string? SenderEmail { get; set; }
    public string? SenderMessage { get; set; }
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
