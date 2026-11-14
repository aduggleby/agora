using System.Reflection;
using Agora.Application.Utilities;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Agora.Web.Agents;

/// <summary>
/// The three tool sets, built once: owner agents with access "own" and "all" (the latter also gets
/// <c>read_share_file</c>) and anonymous upload-link agents. One set is assigned to every request (stateless MCP runs
/// <c>ConfigureSessionOptions</c> per request), so a tool never caches the caller.
/// </summary>
public sealed class McpToolSets
{
    public const string OwnerInstructions =
        "Agora shares files. Use upload_file (small files) or get_upload_url (larger files) to stage files, then create_share to get a link.";
    public const string AnonymousInstructions =
        "This server accepts files for the owner of one upload link. Stage large files with get_upload_url or pass small ones to send_files. " +
        "Give a real sender name and email address.";

    public McpToolSet OwnerOwn { get; } = BuildOwner(includeRead: false);
    public McpToolSet OwnerAll { get; } = BuildOwner(includeRead: true);
    public McpToolSet Anonymous { get; } = Build(typeof(AgoraMcpUploadLinkTools), AnonymousInstructions, _ => true);

    /// <summary>The set for the request's caller, or null when it is neither an agent token nor an anonymous upload-link request.</summary>
    public McpToolSet? For(HttpContext context) => ApiTokenDefaults.AccessLevel(context.User) switch
    {
        ApiTokens.AccessLevels.All => OwnerAll,
        ApiTokens.AccessLevels.Own => OwnerOwn,
        null when McpCaller.UploadCode(context.Request) is not null => Anonymous,
        _ => null
    };

    private static McpToolSet BuildOwner(bool includeRead) =>
        Build(typeof(AgoraMcpOwnerTools), OwnerInstructions, name => includeRead || name != "read_share_file");

    private static McpToolSet Build(Type toolType, string instructions, Func<string, bool> include)
    {
        var tools = new McpServerPrimitiveCollection<McpServerTool>();
        foreach (var method in toolType.GetMethods(BindingFlags.Public | BindingFlags.Instance))
        {
            var attribute = method.GetCustomAttribute<McpServerToolAttribute>();
            if (attribute?.Name is not { } name || !include(name))
            {
                continue;
            }

            tools.Add(McpServerTool.Create(method, ctx => ActivatorUtilities.CreateInstance(ctx.Services!, toolType)));
        }

        return new McpToolSet(tools, instructions);
    }
}

public sealed record McpToolSet(McpServerPrimitiveCollection<McpServerTool> Tools, string Instructions);

/// <summary>How a request to <c>/mcp</c> identifies its caller (KTD2).</summary>
public static class McpCaller
{
    public const string UploadQueryKey = "upload";

    /// <summary>The upload code of an anonymous request: exactly one non-empty <c>upload</c> query value, else null.</summary>
    public static string? UploadCode(HttpRequest request)
    {
        var values = request.Query[UploadQueryKey];
        return values.Count == 1 && !string.IsNullOrWhiteSpace(values[0]) ? values[0] : null;
    }
}

public static class McpSetup
{
    public const string Path = "/mcp";
    /// <summary>Requests may carry inline files (1 MiB of content, base64 inflates it) plus JSON-RPC framing.</summary>
    public const long RequestBodyLimitBytes = 2 * 1024 * 1024;

    public static IServiceCollection AddAgoraMcp(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddSingleton<McpToolSets>();
        services.AddMcpServer().WithHttpTransport(o => o.SessionMode = HttpServerSessionMode.Stateless);
        services.AddOptions<HttpServerTransportOptions>().Configure<McpToolSets>((options, sets) =>
        {
            options.ConfigureSessionOptions = (context, server, _) =>
            {
                var set = sets.For(context) ?? throw new InvalidOperationException("The caller of /mcp was not authorized for any tool set.");
                server.ToolCollection = set.Tools;
                server.ServerInstructions = set.Instructions;
                return Task.CompletedTask;
            };
        });
        return services;
    }

    /// <summary>
    /// Refuses a foreign <c>Origin</c> on <c>/mcp</c> with 403 (DNS rebinding guard). Register it before
    /// <c>UseAuthentication</c> so the answer does not depend on credentials: the endpoint is already selected by routing.
    /// </summary>
    public static WebApplication UseAgoraMcpOrigin(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            if (context.GetEndpoint()?.Metadata.GetMetadata<McpEndpointMetadata>() is not null &&
                context.Request.Headers.TryGetValue("Origin", out var origin) &&
                !OriginMatches(origin.ToString(), context.RequestServices.GetRequiredService<PublicBaseUrlResolver>().Resolve(context.Request)))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.Headers.CacheControl = "no-store";
                await context.Response.WriteAsJsonAsync(new { jsonrpc = "2.0", error = new { code = -32000, message = "Forbidden: unexpected Origin header." } });
                return;
            }

            await next();
        });
        return app;
    }

    public static WebApplication MapAgoraMcp(this WebApplication app)
    {
        app.MapMcp(McpSetup.Path)
            .WithMetadata(ApiEndpointMetadata.Instance, McpEndpointMetadata.Instance, new RequestSizeLimitAttribute(RequestBodyLimitBytes))
            .RequireAuthorization(ApiTokenDefaults.AgentMcpPolicy)
            .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);
        return app;
    }

    internal static bool OriginMatches(string origin, string baseUrl) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var given) && Uri.TryCreate(baseUrl, UriKind.Absolute, out var server) &&
        string.Equals(given.Scheme, server.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(given.IdnHost, server.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        given.Port == server.Port;
}
