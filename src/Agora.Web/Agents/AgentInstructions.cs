using System.Text;
using System.Text.RegularExpressions;
using Agora.Application.Models;

namespace Agora.Web.Agents;

/// <summary>
/// The Markdown an AI agent reads at <c>/u/{code}/llms.txt</c>: what the upload link is for and how to send files to it
/// (MCP or plain HTTP). The owner's display name is the only free text and is escaped, so it cannot add structure.
/// </summary>
public static partial class AgentInstructions
{
    public static string Build(string baseUrl, string code, string? ownerDisplayName, AgoraOptions options)
    {
        var name = EscapeMarkdown(ownerDisplayName);
        var encodedCode = Uri.EscapeDataString(code);
        var pageUrl = $"{baseUrl}/u/{encodedCode}";
        var api = $"{baseUrl}/api/v1/upload-links/{encodedCode}";

        var sb = new StringBuilder();
        sb.AppendLine($"# Send files to {name}");
        sb.AppendLine();
        sb.AppendLine($"This upload link is for files intended for {name}. Send only files you were asked to send to them.");
        sb.AppendLine();
        sb.AppendLine($"- Upload page for people: {pageUrl}");
        sb.AppendLine($"- MCP server: {baseUrl}/mcp?upload={encodedCode}");
        sb.AppendLine();
        sb.AppendLine("## With MCP");
        sb.AppendLine();
        sb.AppendLine($"Connect to `{baseUrl}/mcp?upload={encodedCode}` without signing in. It offers two tools:");
        sb.AppendLine();
        sb.AppendLine($"- `send_files`: sends files inline in one call (at most {FormatBytes(AgentLimits.InlineMaxBytes)} per call in total): `files` (each with `file_name` and exactly one of `text` or `content_base64`) and/or a `draft_id` from `get_upload_url`, plus the sender fields below.");
        sb.AppendLine("- `get_upload_url`: returns an upload URL (`uploadUrl`) and a `draftId` for larger files. Arguments: `file_name`, `size_bytes` and, for each more file, the `draft_id` it returned. Upload the bytes with an HTTP `PUT`, then pass the `draftId` as `draft_id` to `send_files`.");
        sb.AppendLine();
        sb.AppendLine("## Sender fields (MCP argument names; the HTTP API calls them `senderName`, `senderEmail` and `message`)");
        sb.AppendLine();
        sb.AppendLine("- `sender_name`: required, up to 200 characters. Say who you are, for example the agent and the person it acts for.");
        sb.AppendLine("- `sender_email`: required, a valid address, up to 320 characters. The owner sees it and may reply to it.");
        sb.AppendLine("- `message`: optional, up to 2000 characters. Explain what the files are.");
        sb.AppendLine();
        sb.AppendLine("The owner is told that an AI agent sent the files and that the name and email are not verified.");
        sb.AppendLine();
        sb.AppendLine("## With HTTP (curl)");
        sb.AppendLine();
        sb.AppendLine("Send `Content-Type: application/json` on every POST. `jq` is used only to read JSON; any parser works.");
        sb.AppendLine();
        sb.AppendLine("```sh");
        sb.AppendLine($"API='{api}'");
        sb.AppendLine("FILE=./report.pdf");
        sb.AppendLine();
        sb.AppendLine("# 1. Ask for an upload URL for the first file (no draftId yet).");
        sb.AppendLine("RESP=$(curl -sS --fail-with-body -X POST \"$API/upload-urls\" \\");
        sb.AppendLine("  -H 'Content-Type: application/json' \\");
        sb.AppendLine("  -d \"{\\\"fileName\\\":\\\"$(basename \"$FILE\")\\\",\\\"sizeBytes\\\":$(wc -c < \"$FILE\")}\")");
        sb.AppendLine("DRAFT_ID=$(printf '%s' \"$RESP\" | jq -r .draftId)");
        sb.AppendLine("UPLOAD_URL=$(printf '%s' \"$RESP\" | jq -r .uploadUrl)");
        sb.AppendLine();
        sb.AppendLine("# 2. Upload the file's bytes to the returned uploadUrl.");
        sb.AppendLine("curl -sS --fail-with-body -T \"$FILE\" \"$UPLOAD_URL\"");
        sb.AppendLine();
        sb.AppendLine("# Repeat 1 and 2 for each more file, adding the returned draftId to the request of step 1:");
        sb.AppendLine("#   -d \"{\\\"draftId\\\":\\\"$DRAFT_ID\\\",\\\"fileName\\\":\\\"$(basename \"$FILE\")\\\",\\\"sizeBytes\\\":$(wc -c < \"$FILE\")}\"");
        sb.AppendLine();
        sb.AppendLine("# 3. Send everything in the draft.");
        sb.AppendLine("curl -sS --fail-with-body -X POST \"$API/send\" \\");
        sb.AppendLine("  -H 'Content-Type: application/json' \\");
        sb.AppendLine("  -d \"{\\\"draftId\\\":\\\"$DRAFT_ID\\\",\\\"senderName\\\":\\\"Your name\\\",\\\"senderEmail\\\":\\\"you@example.com\\\",\\\"message\\\":\\\"What these files are\\\"}\"");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("`draftId` always comes from the response of step 1; never invent one. A draft can be sent once.");
        sb.AppendLine();
        sb.AppendLine("## Limits");
        sb.AppendLine();
        sb.AppendLine($"- At most {options.MaxFilesPerShare} files per send.");
        sb.AppendLine($"- At most {FormatBytes(options.MaxFileSizeBytes)} per file and {FormatBytes(options.MaxTotalUploadBytes)} in total.");
        sb.AppendLine($"- Inline MCP calls: at most {FormatBytes(AgentLimits.InlineMaxBytes)} per call.");
        sb.AppendLine("- Requests are rate limited; on HTTP 429 wait and retry later.");
        return sb.ToString();
    }

    private static string FormatBytes(long bytes) =>
        bytes >= 1024L * 1024 * 1024 ? $"{bytes / (1024.0 * 1024 * 1024):0.##} GiB" :
        bytes >= 1024L * 1024 ? $"{bytes / (1024.0 * 1024):0.##} MiB" :
        bytes >= 1024 ? $"{bytes / 1024.0:0.##} KiB" : $"{bytes} bytes";

    /// <summary>One line of plain text: control characters become spaces and Markdown punctuation is escaped.</summary>
    internal static string EscapeMarkdown(string? text)
    {
        var value = ControlCharacters().Replace((text ?? string.Empty).Trim(), " ");
        if (value.Length == 0)
        {
            return "this recipient";
        }

        if (value.Length > 200)
        {
            value = value[..200];
        }

        return MarkdownSpecials().Replace(value, "\\$&");
    }

    [GeneratedRegex(@"[\p{C}\u2028\u2029]+")]
    private static partial Regex ControlCharacters();

    [GeneratedRegex(@"[\\`*_{}\[\]()<>#+\-.!|~&]")]
    private static partial Regex MarkdownSpecials();
}
