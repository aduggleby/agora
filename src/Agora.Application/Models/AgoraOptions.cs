namespace Agora.Application.Models;

public sealed class AgoraOptions
{
    public const string Section = "Agora";
    public string? PublicBaseUrl { get; set; }
    public string StorageRoot { get; set; } = "storage";
    public int MaxFilesPerShare { get; set; } = 20;
    public long MaxFileSizeBytes { get; set; } = 250L * 1024 * 1024;
    public long MaxTotalUploadBytes { get; set; } = 1024L * 1024 * 1024;
    public int DownloadEventRetentionDays { get; set; } = 90;
    public int ZombieUploadRetentionHours { get; set; } = 24;
}
