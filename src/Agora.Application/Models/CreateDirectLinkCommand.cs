namespace Agora.Application.Models;

/// <summary>
/// Creates a temporary direct link from the single file staged into <paramref name="DraftShareId"/>.
/// </summary>
public sealed record CreateDirectLinkCommand(
    Guid OwnerUserId,
    string UploaderEmail,
    string UploadId,
    string DraftShareId,
    DirectLinkDuration Duration);
