namespace Agora.Web.Endpoints;

/// <summary>
/// Marks the MCP endpoint (<c>/mcp</c>). Its 401 carries <c>resource_metadata</c> so MCP clients can start OAuth, its
/// requests are subject to the <c>Origin</c> check, and the rate limiter treats it specially (token callers skip the
/// public-upload bucket; every caller is concurrency limited).
/// </summary>
public sealed class McpEndpointMetadata
{
    public static readonly McpEndpointMetadata Instance = new();

    private McpEndpointMetadata()
    {
    }
}
