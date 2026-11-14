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

/// <summary>
/// Marks the anonymous upload-link routes of the agent API. <see cref="InlineBody"/> routes parse a JSON body before
/// any draft is known, so the rate limiter admits at most two of them per address at a time before the body is read.
/// <see cref="TicketPut"/> marks <c>PUT /upload-urls/{ticket}</c>, which uses the public-upload bucket only for tickets
/// of an upload link (owner tickets are authorized by the token that issued them).
/// </summary>
public sealed record AgentUploadRouteMetadata(bool InlineBody = false, bool TicketPut = false);
