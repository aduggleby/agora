namespace Agora.Web.Services;

public static class SharePreviewPaths
{
    public static string Relative(Guid shareId, Guid fileId)
    {
        return Path.Combine("previews", shareId.ToString("N"), $"{fileId}.jpg");
    }

    public static string Absolute(string storageRoot, Guid shareId, Guid fileId)
    {
        return Path.Combine(storageRoot, Relative(shareId, fileId));
    }

    public static string ThumbnailRelative(Guid shareId, Guid fileId)
    {
        return Path.Combine("previews", shareId.ToString("N"), $"{fileId}-thumb.jpg");
    }

    public static string ThumbnailAbsolute(string storageRoot, Guid shareId, Guid fileId)
    {
        return Path.Combine(storageRoot, ThumbnailRelative(shareId, fileId));
    }
}
