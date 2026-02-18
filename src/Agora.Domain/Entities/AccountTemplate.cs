namespace Agora.Domain.Entities;

public sealed class AccountTemplate
{
    public Guid Id { get; set; }
    public string UploaderEmail { get; set; } = string.Empty;
    public string Title { get; set; } = "Shared file";
    public string H1 { get; set; } = "A file was shared with you";
    public string Description { get; set; } = "Use the button below to download your file.";
    public string? BackgroundImageUrl { get; set; }
    public string? BackgroundColorHex { get; set; }
    public string ContainerPosition { get; set; } = "center";
    public DateTime UpdatedAtUtc { get; set; }
}
