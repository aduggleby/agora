using System.ComponentModel;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Agora.Web.Agents;

/// <summary>
/// MCP tools of an anonymous agent bound to one upload link (<c>/mcp?upload={code}</c>). Each tool is a thin call into
/// the upload-link agent service; until that service is wired in, every tool answers that it is not available yet.
/// </summary>
[McpServerToolType]
public sealed class AgoraMcpUploadLinkTools
{
    [McpServerTool(Name = "send_files", Title = "Send files to the upload link owner", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Sends files to the owner of this upload link. Give a real sender name and email address; the owner sees them.")]
    public CallToolResult SendFiles(
        [Description("Name of the sender.")] string sender_name,
        [Description("Email address of the sender.")] string sender_email,
        [Description("Optional message for the owner.")] string? message = null,
        [Description("Draft id returned by get_upload_url when files were uploaded by URL.")] string? draft_id = null) =>
        Unavailable();

    [McpServerTool(Name = "get_upload_url", Title = "Get a one-time upload URL", ReadOnly = false, Destructive = false, Idempotent = false, OpenWorld = false)]
    [Description("Returns a one-time URL that accepts the raw bytes of one larger file with a PUT request; then call send_files with the returned draft id.")]
    public CallToolResult GetUploadUrl(
        [Description("File name including extension.")] string file_name,
        [Description("Exact size in bytes of the file that will be sent.")] long size_bytes,
        [Description("Draft returned by an earlier call; omit for the first file.")] string? draft_id = null) =>
        Unavailable();

    private static CallToolResult Unavailable() => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = "This tool is not available yet." }]
    };
}
