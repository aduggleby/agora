using System.ComponentModel;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Agora.Web.Agents;

/// <summary>
/// MCP tools of an anonymous agent bound to one upload link (<c>/mcp?upload={code}</c>). Each tool is a thin call into
/// <see cref="AgentUploadLinkService"/>, the service behind the HTTP routes, so validation, limits and refusals are
/// the same. The upload code comes only from the <c>upload</c> query of the request, never from a tool argument.
/// </summary>
[McpServerToolType]
public sealed class AgoraMcpUploadLinkTools(IHttpContextAccessor accessor, AgentUploadLinkService service, PublicBaseUrlResolver origin)
{
    [McpServerTool(Name = "send_files", Title = "Send files to the upload link owner", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Sends files to the owner of this upload link. Pass small files inline in files (1 MiB decoded in total) and/or draft_id from get_upload_url. Give a real sender name and email address; the owner sees them. The files are queued for the owner; no share link is returned.")]
    public async Task<CallToolResult> SendFiles(
        [Description("Name of the sender.")] string sender_name,
        [Description("Email address of the sender.")] string sender_email,
        [Description("Small files passed inline: each has file_name and exactly one of text or content_base64.")] McpInlineFile[]? files = null,
        [Description("Optional message for the owner.")] string? message = null,
        [Description("Draft id returned by get_upload_url or an earlier send; omit when only passing files.")] string? draft_id = null,
        [Description("With draft_id: a subset of the staged file ids; default is all.")] string[]? file_ids = null,
        CancellationToken ct = default)
    {
        if (Context() is not { } context)
        {
            return Unavailable();
        }

        var request = new SendFilesRequest(
            draft_id,
            files?.Select(x => new InlineFile(x?.FileName, x?.Text, x?.ContentBase64)).ToList(),
            file_ids,
            sender_name,
            sender_email,
            message);
        return Map(await service.SendAsync(McpCaller.UploadCode(context.Request), origin.Resolve(context.Request), Address(context), request, ct));
    }

    [McpServerTool(Name = "get_upload_url", Title = "Get a one-time upload URL", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Returns a one-time URL that accepts the raw bytes of one larger file with a PUT request (send the exact byte count in Content-Length); then call send_files with the returned draft_id.")]
    public async Task<CallToolResult> GetUploadUrl(
        [Description("File name including extension.")] string file_name,
        [Description("Exact size in bytes of the file that will be sent.")] long size_bytes,
        [Description("Draft returned by an earlier call; omit for the first file.")] string? draft_id = null,
        CancellationToken ct = default) =>
        Context() is not { } context
            ? Unavailable()
            : Map(await service.IssueUploadUrlAsync(McpCaller.UploadCode(context.Request), origin.Resolve(context.Request), Address(context), draft_id, file_name, size_bytes, ct));

    private HttpContext? Context() => accessor.HttpContext;

    private static string Address(HttpContext context) => UploadStagingEndpoints.ClientAddress(context);

    private static CallToolResult Map<T>(AgentResult<T> result) =>
        result.IsOk ? AgoraMcpOwnerTools.Success(result.Value) : AgoraMcpOwnerTools.Refused(result.Status, result.Error!);

    private static CallToolResult Unavailable() => AgoraMcpOwnerTools.Refused(StatusCodes.Status400BadRequest, "No upload link was given.");
}
