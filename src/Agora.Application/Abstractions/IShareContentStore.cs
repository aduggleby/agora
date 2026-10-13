using Agora.Application.Models;

namespace Agora.Application.Abstractions;

public interface IShareContentStore
{
    /// <summary>
    /// Uploads the staged files under a new <c>shares/yyyy/MM/{guid}</c> root. On failure, anything already uploaded is
    /// deleted before the exception propagates.
    /// </summary>
    Task<(string ContentRootPath, IReadOnlyList<StoredShareContentFile> Files)> PersistShareFilesAsync(
        IReadOnlyList<UploadSourceFile> files,
        DateTime nowUtc,
        CancellationToken cancellationToken);

    /// <summary>Deletes a share content root; ignores anything that is not a generated <c>shares/yyyy/MM/{guid}</c> root.</summary>
    Task DeleteContentRootAsync(string? contentRootPath, CancellationToken cancellationToken);
}

/// <param name="StoredRelativePath">Object key of the stored copy.</param>
/// <param name="LocalSourcePath">Local staged file the copy was uploaded from (still present for zip building).</param>
public sealed record StoredShareContentFile(
    string EntryName,
    string StoredRelativePath,
    string LocalSourcePath,
    long SizeBytes,
    string ContentType);
