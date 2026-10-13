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

    public static string LockPath(string storageRoot, Guid shareId, Guid fileId) => MarkerBase(storageRoot, shareId, fileId) + ".lock";

    public static string FailedPath(string storageRoot, Guid shareId, Guid fileId) => MarkerBase(storageRoot, shareId, fileId) + ".failed";

    private static string MarkerBase(string storageRoot, Guid shareId, Guid fileId) =>
        Path.Combine(storageRoot, "previews", shareId.ToString("N"), $"{fileId}.jpg");
}
