using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
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
    /// <summary>Concurrent requests one caller may have in flight on <c>/mcp</c>; its body is parsed before draft admission.</summary>
    public const int McpConcurrentRequests = 2;

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

        var budget = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
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

        // /mcp also admits at most two concurrent requests per caller (per account for agent tokens, else per address).
        // This runs in the middleware, before the endpoint reads any body.
        var mcpConcurrency = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
        {
            if (httpContext.GetEndpoint()?.Metadata.GetMetadata<McpEndpointMetadata>() is null)
            {
                return RateLimitPartition.GetNoLimiter("mcp:none");
            }

            var caller = ApiTokenDefaults.IsApiTokenPrincipal(httpContext.User)
                ? $"account:{httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)}"
                : $"ip:{ClientIp(httpContext)}";
            return RateLimitPartition.GetConcurrencyLimiter(
                partitionKey: $"mcp:{caller}",
                factory: _ => new ConcurrencyLimiterOptions { PermitLimit = McpConcurrentRequests, QueueLimit = 0 });
        });
        options.GlobalLimiter = PartitionedRateLimiter.CreateChained(budget, mcpConcurrency);

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

            // /mcp: anonymous callers share the browser's per-address bucket; agent tokens act as the signed-in owner.
            if (httpContext.GetEndpoint()?.Metadata.GetMetadata<McpEndpointMetadata>() is not null &&
                ApiTokenDefaults.IsApiTokenPrincipal(httpContext.User))
            {
                return RateLimitPartition.GetNoLimiter("public-upload:mcp-token");
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

    // IPv6 clients are grouped by /64 (ClientAddresses), so rotating addresses within a prefix shares one budget.
    private static string ClientIp(HttpContext httpContext) =>
        ClientAddresses.PartitionKey(httpContext.Connection.RemoteIpAddress);
}
