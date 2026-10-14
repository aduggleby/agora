using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Agora.Web.Startup;

/// <summary>
/// Readiness check for GET /ready in S3 mode: the bucket must be listable. Healthy results are cached for 30 s so
/// probes do not hit the object store on every call. The ping is bounded by its own 2 s timeout so the probe answers
/// within the reverse proxy's 3 s budget. A failed or slow ping is only Degraded (HTTP 200) while the last success is
/// less than 2 minutes old, so a brief object-store hiccup does not take the app out of rotation.
/// </summary>
public sealed class ObjectStoreHealthCheck(Func<CancellationToken, Task> ping, TimeProvider timeProvider) : IHealthCheck
{
    internal static readonly TimeSpan PingTimeout = TimeSpan.FromSeconds(2);
    internal static readonly TimeSpan GracePeriod = TimeSpan.FromMinutes(2);
    internal static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(30);

    private long _healthyUntilTicks;
    private long _lastSuccessTicks = long.MinValue;

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow().UtcTicks;
        if (now < Interlocked.Read(ref _healthyUntilTicks))
        {
            return HealthCheckResult.Healthy("Object store reachable (cached).");
        }

        try
        {
            using var timeout = new CancellationTokenSource(PingTimeout, timeProvider);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
            await ping(linked.Token);
            Interlocked.Exchange(ref _healthyUntilTicks, now + CacheDuration.Ticks);
            Interlocked.Exchange(ref _lastSuccessTicks, now);
            return HealthCheckResult.Healthy("Object store reachable.");
        }
        // If the caller itself went away, the exception is not an object-store failure: let the cancellation
        // propagate (no state change, nobody is waiting for a result). Our own timeout still counts as a failure.
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            var lastSuccess = Interlocked.Read(ref _lastSuccessTicks);
            if (lastSuccess != long.MinValue)
            {
                var age = TimeSpan.FromTicks(now - lastSuccess);
                if (age < GracePeriod)
                {
                    return HealthCheckResult.Degraded(
                        $"Object store check failed; last success {(int)age.TotalSeconds} s ago.", ex);
                }
            }

            return HealthCheckResult.Unhealthy("Object store check failed.", ex);
        }
    }

}
