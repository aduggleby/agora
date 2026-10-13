using Agora.Application.Abstractions;
using Agora.Application.Utilities;
using Microsoft.Net.Http.Headers;

namespace Agora.Web.Endpoints;

/// <summary>Serves object-store content through the app (range requests, If-Range, Last-Modified, ETag).</summary>
public static class ObjectResults
{
    /// <summary>
    /// CSP for responses carrying user-derived bytes: no subresources, no script, sandboxed
    /// (the raw.githubusercontent.com pattern). <c>style-src 'unsafe-inline'</c> keeps the
    /// browser's own media/image viewer documents rendering.
    /// </summary>
    public const string UserContentCsp = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

    public static IResult File(ObjectStream obj, string contentType, string? downloadName = null, bool enableRangeProcessing = true) =>
        Results.File(
            obj.Content,
            contentType,
            downloadName,
            obj.Info.LastModified,
            EntityTagHeaderValue.Parse(obj.Info.ETag),
            enableRangeProcessing);

    /// <summary>
    /// Serves user-uploaded content under <see cref="ContentTypePolicy"/>: the type comes from the
    /// file name only, non-allowlisted types are forced to an octet-stream attachment, and the
    /// response is marked nosniff and CSP-sandboxed. <paramref name="forceAttachment"/> turns an
    /// inline-safe file into an attachment (the <c>?download=1</c> path) and always gets the full CSP.
    /// </summary>
    public static IResult UserContent(HttpResponse response, ObjectStream obj, string? fileName, bool forceAttachment = false)
    {
        var plan = ContentTypePolicy.Resolve(fileName);
        var attachment = !plan.Inline || forceAttachment;
        ApplyUserContentHeaders(response, sandbox: SandboxFor(plan, attachment));
        return File(obj, plan.ContentType, attachment ? DownloadName(fileName) : null);
    }

    /// <summary>Same policy for a local scratch file (staged uploads).</summary>
    public static IResult UserContentFile(HttpResponse response, string path, string? fileName)
    {
        var plan = ContentTypePolicy.Resolve(fileName);
        var attachment = !plan.Inline;
        ApplyUserContentHeaders(response, sandbox: SandboxFor(plan, attachment));
        return Results.File(path, plan.ContentType, attachment ? DownloadName(fileName) : null);
    }

    /// <summary>
    /// Headers for every response that carries user-derived bytes (files, archives, backgrounds,
    /// previews, thumbnails, og-image): no sniffing, and <see cref="UserContentCsp"/> so a mis-served
    /// document cannot run script in the site origin. The only caller that passes
    /// <paramref name="sandbox"/> = false is an inline PDF: Chrome's PDF viewer does not render inside
    /// a sandboxed document, and the viewer already runs in an isolated origin. A PDF served as an
    /// attachment keeps the full CSP.
    /// </summary>
    public static void ApplyUserContentHeaders(HttpResponse response, bool sandbox = true)
    {
        response.Headers["X-Content-Type-Options"] = "nosniff";
        if (sandbox)
        {
            response.Headers["Content-Security-Policy"] = UserContentCsp;
        }
    }

    private static bool SandboxFor(ContentTypePolicy.ServePlan plan, bool attachment) =>
        attachment || plan.ContentType != "application/pdf";

    private static string DownloadName(string? fileName)
    {
        var name = Path.GetFileName(fileName ?? string.Empty);
        return string.IsNullOrWhiteSpace(name) ? "download" : name;
    }
}
