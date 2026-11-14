using Agora.Web.Agents;

namespace Agora.Web.Startup;

/// <summary>
/// Wiring of the agent interface (agent HTTP API, MCP endpoint, OAuth discovery, upload-link instructions). Each unit
/// that adds a piece appends its registration or route mapping here, so <c>Program.cs</c> stays untouched.
/// </summary>
public static class AgentSetup
{
    public static IServiceCollection AddAgoraAgents(this IServiceCollection services)
    {
        return services;
    }

    public static WebApplication MapAgoraAgents(this WebApplication app)
    {
        app.MapAgentDiscoveryEndpoints();
        return app;
    }
}
