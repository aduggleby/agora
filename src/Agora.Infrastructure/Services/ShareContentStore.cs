using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

public sealed class ShareContentStore(IOptions<AgoraOptions> options) : IShareContentStore
{
    private readonly AgoraOptions _options = options.Value;

    public Task<(string ContentRootPath, IReadOnlyList<StoredShareContentFile> Files)> PersistShareFilesAsync(
        IReadOnlyList<UploadSourceFile> files,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var shareContentRelativePath = Path.Combine("shares", nowUtc.ToString("yyyy"), nowUtc.ToString("MM"), Guid.NewGuid().ToString("N"));
        var shareContentAbsolutePath = Path.Combine(_options.StorageRoot, shareContentRelativePath);
        Directory.CreateDirectory(shareContentAbsolutePath);

        var storedFiles = new List<StoredShareContentFile>(files.Count);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var entryName = ArchiveNameResolver.Sanitize(file.OriginalFileName);
            var safeExtension = Path.GetExtension(entryName);
            var storedFileName = $"{Guid.NewGuid():N}{safeExtension}";
            var storedRelativePath = Path.Combine(shareContentRelativePath, storedFileName);
            var storedAbsolutePath = Path.Combine(_options.StorageRoot, storedRelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(storedAbsolutePath)!);
            File.Copy(file.TempPath, storedAbsolutePath, overwrite: true);
            storedFiles.Add(new StoredShareContentFile(
                entryName,
                storedRelativePath,
                storedAbsolutePath,
                file.OriginalSizeBytes,
                file.ContentType));
        }

        return Task.FromResult((shareContentRelativePath, (IReadOnlyList<StoredShareContentFile>)storedFiles));
    }

    public string? ResolveAbsolutePath(string? storedRelativePath)
    {
        var relative = (storedRelativePath ?? string.Empty).Trim().TrimStart('/').TrimStart('\\');
        if (relative.Length == 0)
        {
            return null;
        }

        var storageRoot = Path.GetFullPath(_options.StorageRoot);
        var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relative));
        return absolutePath.StartsWith(storageRoot, StringComparison.Ordinal)
            ? absolutePath
            : null;
    }

    public void DeleteContentRoot(string? contentRootPath)
    {
        var contentRelativePath = (contentRootPath ?? string.Empty).TrimStart('/', '\\');
        if (contentRelativePath.Length == 0)
        {
            return;
        }

        var normalizedContentPath = contentRelativePath.Replace('\\', '/');
        if (!normalizedContentPath.StartsWith("shares/", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var contentAbsolutePath = Path.Combine(_options.StorageRoot, contentRelativePath);
        if (Directory.Exists(contentAbsolutePath))
        {
            Directory.Delete(contentAbsolutePath, recursive: true);
        }
    }
}
