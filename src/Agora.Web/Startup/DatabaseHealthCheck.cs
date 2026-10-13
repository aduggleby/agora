using Agora.Infrastructure.Persistence;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Agora.Web.Startup;

/// <summary>
/// Readiness check for GET /ready: healthy when the application database accepts connections.
/// GET /live runs no checks (process up only).
/// </summary>
public sealed class DatabaseHealthCheck(AgoraDbContext db) : IHealthCheck
{
    /// <summary>Tag used to select this check for /ready.</summary>
    public const string ReadyTag = "ready";

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy("Database reachable.")
                : HealthCheckResult.Unhealthy("Database not reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database check failed.", ex);
        }
    }
}
