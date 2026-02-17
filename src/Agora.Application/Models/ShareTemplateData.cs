namespace Agora.Application.Models;

public sealed record ShareTemplateData(
    string Title,
    string H1,
    string Description,
    string? BackgroundImageUrl);
