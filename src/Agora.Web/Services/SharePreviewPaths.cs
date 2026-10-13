namespace Agora.Web.Services;

/// <summary>
/// Preview object keys (durable, in the object store) and the local paths of their .lock/.failed markers (scratch,
/// always under StorageRoot).
/// </summary>
public static class SharePreviewPaths
{
    public static string Prefix(Guid shareId) => $"previews/{shareId:N}/";

    public static string Key(Guid shareId, Guid fileId) => $"{Prefix(shareId)}{fileId}.jpg";

    public static string ThumbnailKey(Guid shareId, Guid fileId) => $"{Prefix(shareId)}{fileId}-thumb.jpg";

    /// <summary>Cached link-preview (Open Graph) image of the share, purged with the rest of the prefix.</summary>
    public static string OgImageKey(Guid shareId) => $"{Prefix(shareId)}og.png";

    public static string LockPath(string storageRoot, Guid shareId, Guid fileId) => MarkerBase(storageRoot, shareId, fileId) + ".lock";

    public static string FailedPath(string storageRoot, Guid shareId, Guid fileId) => MarkerBase(storageRoot, shareId, fileId) + ".failed";

    /// <summary>Written when a generation job is enqueued; anonymous viewers may enqueue again only once it is stale.</summary>
    public static string QueuedPath(string storageRoot, Guid shareId, Guid fileId) => MarkerBase(storageRoot, shareId, fileId) + ".queued";

    private static string MarkerBase(string storageRoot, Guid shareId, Guid fileId) =>
        Path.Combine(storageRoot, "previews", shareId.ToString("N"), $"{fileId}.jpg");
}
