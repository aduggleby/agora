namespace Agora.Domain.Entities;

public sealed class ShareFile
{
    public Guid Id { get; set; }
    public Guid ShareId { get; set; }
    public Share Share { get; set; } = default!;
    public string OriginalFilename { get; set; } = string.Empty;
    public long OriginalSizeBytes { get; set; }
    public string DetectedContentType { get; set; } = "application/octet-stream";
}
