using Microsoft.AspNetCore.Mvc;
using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Agora.Web.Agents;

/// <summary>Per-link instructions for AI agents (<c>GET /u/{code}/llms.txt</c>), served only while the owner allows agent uploads.</summary>
public static class AgentDiscoveryEndpoints
{
    public static IEndpointRouteBuilder MapAgentDiscoveryEndpoints(this IEndpointRouteBuilder app)
    {
        // ApiEndpointMetadata: the CSRF middleware sets no cookie and runs no antiforgery on this route.
        app.MapGet("/u/{code}/llms.txt", async (string code, HttpContext context, [FromServices] AuthService auth, [FromServices] PublicBaseUrlResolver baseUrls, [FromServices] IOptions<AgoraOptions> options, CancellationToken ct) =>
            {
                var user = await auth.FindByUploadTokenAsync((code ?? string.Empty).Trim(), ct);
                if (user is null || !user.AllowAgentUploads)
                {
                    return Results.Text("Upload link not found.", "text/plain; charset=utf-8", statusCode: StatusCodes.Status404NotFound);
                }

                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["X-Robots-Tag"] = "noindex";
                context.Response.Headers.XContentTypeOptions = "nosniff";
                return Results.Text(
                    AgentInstructions.Build(baseUrls.Resolve(context.Request), user.UploadToken, user.DisplayName, options.Value),
                    "text/markdown; charset=utf-8");
            })
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints)
            .WithMetadata(ApiEndpointMetadata.Instance);

        return app;
    }
}
