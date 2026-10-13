using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Agora.Application.Models;
using Microsoft.AspNetCore.RateLimiting;

namespace Agora.Web.Startup;

/// <summary>
/// Rate limiting: a global per-client budget (authenticated users per account, anonymous clients per IP) plus the
/// named policies endpoints opt into. Every per-IP key relies on the forwarded-headers middleware having already
/// replaced RemoteIpAddress for trusted proxies. Health endpoints and static files are not limited: the health
/// endpoints carry DisableRateLimiting, static files are served before the limiter runs.
/// </summary>
public static class RateLimitSetup
{
    public const string AuthEndpoints = "AuthEndpoints";
    public const string DownloadEndpoints = "DownloadEndpoints";
    public const string PublicUploadEndpoints = "PublicUploadEndpoints";

    public static void Configure(RateLimiterOptions options, AgoraRateLimitOptions limits, bool isE2E)
    {
        // 0 (or negative) disables the anonymous site-wide budget; the named per-endpoint policies still apply.
        var anonymousPerMinute = limits.AnonymousPerMinute;
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.OnRejected = static (context, _) =>
        {
            if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            {
                var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
                context.HttpContext.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
            }

            return ValueTask.CompletedTask;
        };

        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            if (httpContext.User.Identity?.IsAuthenticated != true)
            {
                // E2E suites hammer anonymous pages far more than a real client; don't throttle them.
                if (isE2E || anonymousPerMinute <= 0)
                {
                    return RateLimitPartition.GetNoLimiter("anonymous");
                }

                return RateLimitPartition.GetSlidingWindowLimiter(
                    partitionKey: $"anonymous:{ClientIp(httpContext)}",
                    factory: _ => new SlidingWindowRateLimiterOptions
                    {
                        PermitLimit = anonymousPerMinute,
                        Window = TimeSpan.FromMinutes(1),
                        SegmentsPerWindow = 6,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            }

            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? httpContext.User.FindFirstValue(ClaimTypes.Email)
                         ?? "authenticated";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"authenticated:{userId}",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 120,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        });

        options.AddPolicy(AuthEndpoints, httpContext =>
        {
            // E2E suites log in far more often than a real client; don't throttle them.
            if (isE2E)
            {
                return RateLimitPartition.GetNoLimiter("auth:e2e");
            }

            return RateLimitPartition.GetSlidingWindowLimiter(
                partitionKey: $"auth:{ClientIp(httpContext)}",
                factory: _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = 10,
                    Window = TimeSpan.FromMinutes(1),
                    SegmentsPerWindow = 4,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        });

        options.AddPolicy(DownloadEndpoints, httpContext =>
        {
            var token = httpContext.Request.RouteValues.TryGetValue("token", out var tokenValue)
                ? tokenValue?.ToString() ?? "unknown"
                : "unknown";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"download:{token}:{ClientIp(httpContext)}",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 20,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        });

        options.AddPolicy(PublicUploadEndpoints, httpContext =>
        {
            // E2E suites stage far more files from one address than a real client; don't throttle them.
            if (isE2E)
            {
                return RateLimitPartition.GetNoLimiter("public-upload:e2e");
            }

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: $"public-upload:{ClientIp(httpContext)}",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 25,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        });
    }

    private static string ClientIp(HttpContext httpContext) =>
        httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
