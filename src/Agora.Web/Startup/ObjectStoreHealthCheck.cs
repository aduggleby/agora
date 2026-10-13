using Agora.Infrastructure.Storage;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Agora.Web.Startup;

/// <summary>
/// Readiness check for GET /ready in S3 mode: the bucket must be listable. Healthy results are cached for 30 s so
/// probes do not hit the object store on every call; failures are never cached.
/// </summary>
public sealed class ObjectStoreHealthCheck(S3ObjectStore store, TimeProvider timeProvider) : IHealthCheck
{
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);
    private long _healthyUntilTicks;

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow().UtcTicks;
        if (now < Interlocked.Read(ref _healthyUntilTicks))
        {
            return HealthCheckResult.Healthy("Object store reachable (cached).");
        }

        try
        {
            await store.PingAsync(cancellationToken);
            Interlocked.Exchange(ref _healthyUntilTicks, now + CacheDuration.Ticks);
            return HealthCheckResult.Healthy("Object store reachable.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Object store check failed.", ex);
        }
    }
}
