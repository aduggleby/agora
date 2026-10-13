using Agora.Application.Abstractions;
using Agora.Application.Utilities;

namespace Agora.Infrastructure.Storage;

/// <summary>
/// Object store rooted at a local directory (the default: StorageRoot, so existing installs keep their data in place).
/// Writes go to a sibling temp file and are moved into place atomically.
/// </summary>
public sealed class FileSystemObjectStore(string rootPath) : IObjectStore
{
    private readonly string _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));

    public async Task PutFileAsync(string key, string localPath, string? contentType, CancellationToken ct)
    {
        var path = Resolve(key);
        await WriteAtomicallyAsync(path, async temp =>
        {
            await using var source = File.OpenRead(localPath);
            await using var target = File.Create(temp);
            await source.CopyToAsync(target, ct);
        });
    }

    public Task PutBytesAsync(string key, byte[] content, string? contentType, CancellationToken ct) =>
        WriteAtomicallyAsync(Resolve(key), temp => File.WriteAllBytesAsync(temp, content, ct));

    public Task<ObjectInfo?> GetInfoAsync(string key, CancellationToken ct)
    {
        var file = new FileInfo(Resolve(key));
        return Task.FromResult(file.Exists ? ToInfo(file.Length, file.LastWriteTimeUtc) : null);
    }

    public Task<ObjectStream?> OpenReadAsync(string key, CancellationToken ct)
    {
        FileStream stream;
        try
        {
            stream = new FileStream(Resolve(key), FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 64 * 1024, useAsync: true);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return Task.FromResult<ObjectStream?>(null);
        }

        try
        {
            // Metadata from the open handle, so a concurrent delete of the path cannot make it fail or mismatch.
            var lastWriteUtc = File.GetLastWriteTimeUtc(stream.SafeFileHandle);
            return Task.FromResult<ObjectStream?>(new ObjectStream(stream, ToInfo(stream.Length, lastWriteUtc)));
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    public async Task DownloadToFileAsync(string key, string localPath, CancellationToken ct)
    {
        var path = Resolve(key);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Object not found.", key);
        }

        await using var source = File.OpenRead(path);
        await using var target = File.Create(localPath);
        await source.CopyToAsync(target, ct);
    }

    public Task DeleteAsync(string key, CancellationToken ct)
    {
        var path = Resolve(key);
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        return Task.CompletedTask;
    }

    public Task DeletePrefixAsync(string prefix, CancellationToken ct)
    {
        var directory = Resolve(ObjectKey.NormalizePrefix(prefix).TrimEnd('/'));
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }

        return Task.CompletedTask;
    }

    public async Task CopyAsync(string sourceKey, string destinationKey, CancellationToken ct)
    {
        var source = Resolve(sourceKey);
        if (!File.Exists(source))
        {
            throw new FileNotFoundException("Object not found.", sourceKey);
        }

        await WriteAtomicallyAsync(Resolve(destinationKey), temp =>
        {
            File.Copy(source, temp, overwrite: true);
            return Task.CompletedTask;
        });
    }

    private string Resolve(string key)
    {
        var path = Path.GetFullPath(Path.Combine(_root, ObjectKey.Normalize(key)));
        if (!path.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new ArgumentException($"Object key '{key}' escapes the storage root.", nameof(key));
        }

        return path;
    }

    private static async Task WriteAtomicallyAsync(string path, Func<string, Task> write)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await write(temp);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    private static ObjectInfo ToInfo(long length, DateTime lastWriteUtc) =>
        new(length, new DateTimeOffset(lastWriteUtc, TimeSpan.Zero), $"\"{lastWriteUtc.Ticks:x}-{length:x}\"");
}
