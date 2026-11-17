namespace Agora.Application.Models;

/// <summary>
/// Creates a temporary direct link from the single file staged into <paramref name="DraftShareId"/>.
/// <paramref name="CreatedByApiTokenId"/> is the agent token that created it (scopes level "own" agents).
/// </summary>
public sealed record CreateDirectLinkCommand(
    Guid OwnerUserId,
    string UploaderEmail,
    string UploadId,
    string DraftShareId,
    DirectLinkDuration Duration,
    Guid? CreatedByApiTokenId = null);
