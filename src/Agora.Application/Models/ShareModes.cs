namespace Agora.Application.Models;

public enum ShareExperienceType
{
    Archive = 0,
    Gallery = 1
}

public enum ShareAccessMode
{
    DownloadOnly = 0,
    PreviewOnly = 1,
    PreviewAndDownload = 2,
    /// <summary>Single file served as raw bytes at <c>/s/{token}</c>; no download page, no archive, no preview routes.</summary>
    DirectLink = 3
}

public static class ShareModes
{
    public static ShareExperienceType ParseExperienceType(string? raw)
    {
        var value = raw?.Trim().ToLowerInvariant();
        return value switch
        {
            "gallery" => ShareExperienceType.Gallery,
            _ => ShareExperienceType.Archive
        };
    }

    public static string ToStorageValue(ShareExperienceType value)
    {
        return value switch
        {
            ShareExperienceType.Gallery => "gallery",
            _ => "archive"
        };
    }

    public static ShareAccessMode ParseAccessMode(string? raw)
    {
        var value = raw?.Trim().ToLowerInvariant();
        return value switch
        {
            "preview_only" => ShareAccessMode.PreviewOnly,
            "preview_and_download" => ShareAccessMode.PreviewAndDownload,
            "direct_link" => ShareAccessMode.DirectLink,
            _ => ShareAccessMode.DownloadOnly
        };
    }

    public static string ToStorageValue(ShareAccessMode value)
    {
        return value switch
        {
            ShareAccessMode.PreviewOnly => "preview_only",
            ShareAccessMode.PreviewAndDownload => "preview_and_download",
            ShareAccessMode.DirectLink => "direct_link",
            _ => "download_only"
        };
    }

    public static bool AllowsPreview(ShareAccessMode value)
    {
        return value is ShareAccessMode.PreviewOnly or ShareAccessMode.PreviewAndDownload;
    }

    public static bool AllowsZipDownload(ShareAccessMode value)
    {
        return value is ShareAccessMode.DownloadOnly or ShareAccessMode.PreviewAndDownload;
    }

    public static bool IsDirectLink(ShareAccessMode value) => value == ShareAccessMode.DirectLink;

    /// <summary>Convenience for stored values: true when <paramref name="raw"/> is <c>direct_link</c>.</summary>
    public static bool IsDirectLink(string? raw) => IsDirectLink(ParseAccessMode(raw));
}
