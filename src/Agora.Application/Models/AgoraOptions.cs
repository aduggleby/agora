namespace Agora.Application.Models;

public sealed class AgoraOptions
{
    public const string Section = "Agora";
    public string? PublicBaseUrl { get; set; }
    public string StorageRoot { get; set; } = "storage";
    public int MaxFilesPerShare { get; set; } = 20;
    public long MaxFileSizeBytes { get; set; } = 5L * 1024 * 1024 * 1024;
    public long MaxTotalUploadBytes { get; set; } = 10L * 1024 * 1024 * 1024;
    public int DownloadEventRetentionDays { get; set; } = 90;
    public int ZombieUploadRetentionHours { get; set; } = 24;
    public AgoraPreviewOptions Previews { get; set; } = new();
}

/// <summary>
/// Budgets for preview and thumbnail generation of uploaded files. Sources above a budget are not decoded at all;
/// the share shows the "preview unavailable" image instead.
/// </summary>
public sealed class AgoraPreviewOptions
{
    /// <summary>Largest image or PDF (in bytes) that is opened for a preview.</summary>
    public long MaxSourceBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>Largest image (width times height) that is decoded for a preview; checked from the header before decoding.</summary>
    public long MaxSourcePixels { get; set; } = 50_000_000;

    /// <summary>Wall-clock budget for generating one preview or thumbnail.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}
