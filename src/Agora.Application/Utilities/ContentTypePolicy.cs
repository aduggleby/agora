namespace Agora.Application.Utilities;

/// <summary>
/// Single source of truth for how user-uploaded content is typed and served.
/// The content type is derived from the file extension only; the type a client
/// declares in a multipart upload is never trusted. Only a short allowlist of
/// types may be served inline; everything else is served as
/// <c>application/octet-stream</c> with <c>Content-Disposition: attachment</c>.
/// </summary>
public static class ContentTypePolicy
{
    public const string OctetStream = "application/octet-stream";

    /// <summary>How a stored file must be sent back to a browser.</summary>
    public sealed record ServePlan(string ContentType, bool Inline);

    private static readonly Dictionary<string, string> ExtensionMap = new(StringComparer.Ordinal)
    {
        // raster images (inline)
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
        [".webp"] = "image/webp",
        [".avif"] = "image/avif",
        [".bmp"] = "image/bmp",
        // video (inline)
        [".mp4"] = "video/mp4",
        [".m4v"] = "video/mp4",
        [".webm"] = "video/webm",
        [".mov"] = "video/quicktime",
        [".ogv"] = "video/ogg",
        // audio (inline)
        [".mp3"] = "audio/mpeg",
        [".wav"] = "audio/wav",
        [".ogg"] = "audio/ogg",
        [".oga"] = "audio/ogg",
        [".m4a"] = "audio/mp4",
        [".aac"] = "audio/aac",
        [".flac"] = "audio/flac",
        [".weba"] = "audio/webm",
        // documents
        [".pdf"] = "application/pdf",
        [".txt"] = "text/plain",
        [".log"] = "text/plain",
        // known but never inline
        [".svg"] = "image/svg+xml",
        [".svgz"] = "image/svg+xml",
        [".html"] = "text/html",
        [".htm"] = "text/html",
        [".xhtml"] = "application/xhtml+xml",
        [".xml"] = "text/xml",
        [".js"] = "text/javascript",
        [".mjs"] = "text/javascript",
        [".css"] = "text/css",
        [".json"] = "application/json",
        [".md"] = "text/markdown",
        [".csv"] = "text/csv",
        [".zip"] = "application/zip"
    };

    private static readonly HashSet<string> InlineSafeTypes = new(StringComparer.Ordinal)
    {
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/bmp",
        "video/mp4",
        "video/webm",
        "video/quicktime",
        "video/ogg",
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "audio/mp4",
        "audio/aac",
        "audio/flac",
        "audio/webm",
        "application/pdf",
        "text/plain"
    };

    /// <summary>Content type derived from the extension of <paramref name="fileName"/>; unknown extensions map to <see cref="OctetStream"/>.</summary>
    public static string FromFileName(string? fileName)
    {
        var extension = NormalizeExtension(fileName);
        return extension.Length > 0 && ExtensionMap.TryGetValue(extension, out var contentType)
            ? contentType
            : OctetStream;
    }

    /// <summary>
    /// Decides the response content type and disposition for a stored file. Any stored or
    /// client-declared type is ignored on purpose; only the extension counts.
    /// </summary>
    public static ServePlan Resolve(string? fileName)
    {
        var contentType = FromFileName(fileName);
        return InlineSafeTypes.Contains(contentType)
            ? new ServePlan(contentType, Inline: true)
            : new ServePlan(OctetStream, Inline: false);
    }

    /// <summary>True when the extension denotes a raster image that may be rendered inline (SVG excluded).</summary>
    public static bool IsRasterImage(string? fileName)
    {
        var contentType = FromFileName(fileName);
        return contentType.StartsWith("image/", StringComparison.Ordinal) && InlineSafeTypes.Contains(contentType);
    }

    /// <summary>Extensions accepted for download-page background images.</summary>
    public static bool IsAllowedBackgroundImage(string? fileName)
    {
        return NormalizeExtension(fileName) is ".jpg" or ".jpeg" or ".png" or ".webp";
    }

    private static string NormalizeExtension(string? fileName)
    {
        return (Path.GetExtension(fileName ?? string.Empty) ?? string.Empty).Trim().ToLowerInvariant();
    }
}
