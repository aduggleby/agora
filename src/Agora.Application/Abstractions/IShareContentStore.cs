using Agora.Application.Models;

namespace Agora.Application.Abstractions;

public interface IShareContentStore
{
    Task<(string ContentRootPath, IReadOnlyList<StoredShareContentFile> Files)> PersistShareFilesAsync(
        IReadOnlyList<UploadSourceFile> files,
        DateTime nowUtc,
        CancellationToken cancellationToken);

    string? ResolveAbsolutePath(string? storedRelativePath);

    void DeleteContentRoot(string? contentRootPath);
}

public sealed record StoredShareContentFile(
    string EntryName,
    string StoredRelativePath,
    string StoredAbsolutePath,
    long SizeBytes,
    string ContentType);
