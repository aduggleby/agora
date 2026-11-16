using Agora.Infrastructure.Persistence;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Agora.Web.Startup;

/// <summary>
/// Readiness check for GET /ready: healthy when the application database accepts connections.
/// GET /live runs no checks (process up only). The check is bounded by its own 2 s timeout so a slow database
/// yields a real Unhealthy (503) within the reverse proxy's 3 s probe budget instead of an aborted probe.
/// </summary>
public sealed class DatabaseHealthCheck(Func<CancellationToken, Task<bool>> canConnect) : IHealthCheck
{
    /// <summary>Tag used to select this check for /ready.</summary>
    public const string ReadyTag = "ready";

    internal static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(2);

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        using var timeout = new CancellationTokenSource(CheckTimeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            return await canConnect(linked.Token)
                ? HealthCheckResult.Healthy("Database reachable.")
                : HealthCheckResult.Unhealthy("Database not reachable.");
        }
        // A prober that hangs up (reverse proxy reload, client timeout) cancels the request: that is not a database
        // failure, so let the cancellation propagate (Kestrel logs it at Debug) instead of logging Unhealthy at Error.
        // Our own timeout still counts as a failure.
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            return HealthCheckResult.Unhealthy("Database check failed.", ex);
        }
    }
}

public static class DatabaseHealthCheckSetup
{
    /// <summary>Registers the health check service with the database readiness check (tag <see cref="DatabaseHealthCheck.ReadyTag"/>).</summary>
    public static IHealthChecksBuilder AddAgoraDatabaseHealthCheck(this IServiceCollection services)
    {
        services.AddScoped(sp => new DatabaseHealthCheck(sp.GetRequiredService<AgoraDbContext>().Database.CanConnectAsync));
        return services.AddHealthChecks()
            .AddCheck<DatabaseHealthCheck>("database", tags: [DatabaseHealthCheck.ReadyTag], timeout: TimeSpan.FromSeconds(5));
    }
}
