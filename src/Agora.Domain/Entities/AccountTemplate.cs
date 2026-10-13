namespace Agora.Domain.Entities;

public sealed class AccountTemplate
{
    public Guid Id { get; set; }
    /// <summary>Owning <see cref="UserAccount"/>; null only for legacy rows that could not be backfilled.</summary>
    public Guid? OwnerUserId { get; set; }
    public string UploaderEmail { get; set; } = string.Empty;
    public string Title { get; set; } = "Shared file";
    public string H1 { get; set; } = "A file was shared with you";
    public string Description { get; set; } = string.Empty;
    public string? BackgroundImageUrl { get; set; }
    public string? BackgroundColorHex { get; set; }
    public string ContainerPosition { get; set; } = "center";
    public DateTime UpdatedAtUtc { get; set; }
}
