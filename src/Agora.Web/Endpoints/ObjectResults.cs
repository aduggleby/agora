using Agora.Application.Abstractions;
using Microsoft.Net.Http.Headers;

namespace Agora.Web.Endpoints;

/// <summary>Serves object-store content through the app (range requests, If-Range, Last-Modified, ETag).</summary>
public static class ObjectResults
{
    public static IResult File(ObjectStream obj, string contentType, string? downloadName = null, bool enableRangeProcessing = true) =>
        Results.File(
            obj.Content,
            contentType,
            downloadName,
            obj.Info.LastModified,
            EntityTagHeaderValue.Parse(obj.Info.ETag),
            enableRangeProcessing);
}
