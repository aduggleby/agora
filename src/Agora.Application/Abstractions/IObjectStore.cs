namespace Agora.Application.Abstractions;

/// <summary>
/// Durable content store (share files, archives, backgrounds, previews). Keys are relative, forward-slash paths
/// validated by <see cref="Utilities.ObjectKey"/>. Scratch files never go through this abstraction.
/// </summary>
public interface IObjectStore
{
    /// <summary>Uploads a local file (multipart for large files on S3). Overwrites an existing object.</summary>
    Task PutFileAsync(string key, string localPath, string? contentType, CancellationToken ct);

    Task PutBytesAsync(string key, byte[] content, string? contentType, CancellationToken ct);

    /// <summary>Returns null when the object does not exist.</summary>
    Task<ObjectInfo?> GetInfoAsync(string key, CancellationToken ct);

    /// <summary>Opens a seekable, read-only stream plus its metadata; null when the object does not exist.</summary>
    Task<ObjectStream?> OpenReadAsync(string key, CancellationToken ct);

    /// <summary>Copies the object to a local file. Throws <see cref="FileNotFoundException"/> when it does not exist.</summary>
    Task DownloadToFileAsync(string key, string localPath, CancellationToken ct);

    /// <summary>Deletes the object; a missing object is not an error.</summary>
    Task DeleteAsync(string key, CancellationToken ct);

    /// <summary>Deletes every object under the prefix (at least two segments, trailing '/').</summary>
    Task DeletePrefixAsync(string prefix, CancellationToken ct);

    Task CopyAsync(string sourceKey, string destinationKey, CancellationToken ct);
}

/// <param name="ETag">Quoted strong entity tag, e.g. <c>"abc123"</c>.</param>
public sealed record ObjectInfo(long Length, DateTimeOffset LastModified, string ETag);

public sealed record ObjectStream(Stream Content, ObjectInfo Info);
