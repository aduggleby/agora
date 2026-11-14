using Agora.Web.Agents;
using Agora.Web.Endpoints;
using Agora.Application.Models;
using Microsoft.Extensions.Options;

namespace Agora.Web.Startup;

/// <summary>
/// Wiring of the agent interface (agent HTTP API, MCP endpoint, OAuth discovery, upload-link instructions). Each unit
/// that adds a piece appends its registration or route mapping here, so <c>Program.cs</c> stays untouched.
/// </summary>
public static class AgentSetup
{
    public static IServiceCollection AddAgoraAgents(this IServiceCollection services)
    {
        services.AddSingleton<OAuthClientCodec>();
        services.AddSingleton<AgentTicketStore>();
        services.AddScoped<AgentShareService>();
        services.AddScoped<AgentUploadLinkService>();
        services.AddScoped<IPublicDraftAdmission>(sp => sp.GetRequiredService<AgentUploadLinkService>());
        services.AddAgoraMcp();
        return services;
    }

    public static WebApplication MapAgoraAgents(this WebApplication app)
    {
        app.MapAgentDiscoveryEndpoints();
        app.MapOAuthEndpoints();
        app.MapAgentUploadLinkEndpoints();
        app.MapAgentOwnerEndpoints(app.Services.GetRequiredService<IOptions<AgoraOptions>>().Value.MaxFileSizeBytes + 1024 * 1024);
        app.MapAgoraMcp();
        return app;
    }
}
