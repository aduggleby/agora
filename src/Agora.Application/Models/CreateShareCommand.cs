namespace Agora.Application.Models;

public sealed class CreateShareCommand
{
    public required string UploaderEmail { get; init; }
    public string? Message { get; init; }
    public string? ZipFileName { get; init; }
    public required ExpiryMode ExpiryMode { get; init; }
    public DateTime? ExpiresAtUtc { get; init; }
    public required string NotifyMode { get; init; }
    public required TemplateMode TemplateMode { get; init; }
    public string? TemplateTitle { get; init; }
    public string? TemplateH1 { get; init; }
    public string? TemplateDescription { get; init; }
    public string? TemplateBackgroundImageUrl { get; init; }
    public string? TemplateBackgroundColorHex { get; init; }
    public UploadSourceFile? TemplateBackgroundFile { get; init; }
    public required IReadOnlyList<UploadSourceFile> Files { get; init; }
}
