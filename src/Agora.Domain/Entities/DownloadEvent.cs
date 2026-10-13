namespace Agora.Domain.Entities;

public sealed class DownloadEvent
{
    public Guid Id { get; set; }
    public Guid ShareId { get; set; }
    public Share Share { get; set; } = default!;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string BrowserMetadataJson { get; set; } = "{}";
    public DateTime DownloadedAtUtc { get; set; }
    public bool NotificationSent { get; set; }
    public string? NotificationError { get; set; }
}
