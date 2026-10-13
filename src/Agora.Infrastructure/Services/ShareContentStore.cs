using System.Text.RegularExpressions;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;

namespace Agora.Infrastructure.Services;

public sealed partial class ShareContentStore(IObjectStore objectStore) : IShareContentStore
{
    public async Task<(string ContentRootPath, IReadOnlyList<StoredShareContentFile> Files)> PersistShareFilesAsync(
        IReadOnlyList<UploadSourceFile> files,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var contentRoot = $"shares/{nowUtc:yyyy}/{nowUtc:MM}/{Guid.NewGuid():N}";
        var storedFiles = new List<StoredShareContentFile>(files.Count);
        // Entry names are unique within a share (case-insensitively, as most extractors treat them): the same
        // value names the zip entry and the file on the download page.
        var takenEntryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var entryName = ArchiveNameResolver.Deduplicate(ArchiveNameResolver.Sanitize(file.OriginalFileName), takenEntryNames);
                var key = $"{contentRoot}/{Guid.NewGuid():N}{Path.GetExtension(entryName)}";
                await objectStore.PutFileAsync(key, file.TempPath, file.ContentType, cancellationToken);
                storedFiles.Add(new StoredShareContentFile(entryName, key, file.TempPath, file.OriginalSizeBytes, file.ContentType));
            }
        }
        catch
        {
            try
            {
                using var cleanup = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                await objectStore.DeletePrefixAsync(contentRoot + "/", cleanup.Token);
            }
            catch
            {
                // Best effort; the original failure is what matters to the caller.
            }

            throw;
        }

        return (contentRoot, storedFiles);
    }

    public async Task DeleteContentRootAsync(string? contentRootPath, CancellationToken cancellationToken)
    {
        var root = (contentRootPath ?? string.Empty).Replace('\\', '/').TrimEnd('/');
        if (ContentRootPattern().IsMatch(root))
        {
            await objectStore.DeletePrefixAsync(root + "/", cancellationToken);
        }
    }

    [GeneratedRegex("^shares/[0-9]{4}/[0-9]{2}/[0-9a-f]{32}$")]
    private static partial Regex ContentRootPattern();
}
