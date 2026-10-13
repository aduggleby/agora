using Agora.Infrastructure.Persistence;
using Microsoft.AspNetCore.SignalR;

namespace Agora.Web.Auth;

/// <summary>
/// SignalR caches the principal for the lifetime of a connection, so the cookie's OnValidatePrincipal never runs
/// for it. This filter applies the same decision (<see cref="CookieSessions.Validate"/>) on connect and on every hub
/// method call, at most every revalidation interval, and aborts the connection when the session is rejected.
/// Share-progress connections live only while a share is being created, so no periodic sweep of idle connections
/// is needed: a disabled or re-credentialed user loses the connection at their next call or reconnect.
/// </summary>
public sealed class SessionRevalidationHubFilter : IHubFilter
{
    private const string LastCheckKey = "agora:revalidated_at";

    public async Task OnConnectedAsync(HubLifetimeContext context, Func<HubLifetimeContext, Task> next)
    {
        await EnsureSessionAsync(context.Context, context.ServiceProvider, context.Context.ConnectionAborted);
        await next(context);
    }

    public async ValueTask<object?> InvokeMethodAsync(HubInvocationContext invocationContext, Func<HubInvocationContext, ValueTask<object?>> next)
    {
        await EnsureSessionAsync(invocationContext.Context, invocationContext.ServiceProvider, invocationContext.Context.ConnectionAborted);
        return await next(invocationContext);
    }

    private static async Task EnsureSessionAsync(HubCallerContext connection, IServiceProvider services, CancellationToken cancellationToken)
    {
        var principal = connection.User;
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return;
        }

        // The cached principal's timestamp never advances, so remember the last successful check per connection.
        var nowUtc = CookieSessions.NowUtc(services);
        var lastCheck = connection.Items.TryGetValue(LastCheckKey, out var stored) && stored is DateTime storedAt
            ? storedAt
            : CookieSessions.RevalidatedAt(principal);
        if (!CookieSessions.IsRevalidationDue(lastCheck, nowUtc, CookieSessions.RevalidationInterval(services)))
        {
            return;
        }

        var user = await CookieSessions.CheckAsync(services.GetRequiredService<AgoraDbContext>(), principal, cancellationToken);
        if (user is null)
        {
            connection.Abort();
            throw new HubException("Session is no longer valid.");
        }

        connection.Items[LastCheckKey] = nowUtc;
    }
}
