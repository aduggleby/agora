using Agora.Infrastructure.Persistence;
using Agora.Web.Startup;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Agora.Application.Tests;

public sealed class DatabaseHealthCheckTests
{
    private static readonly HealthCheckContext Context = new();

    // Like Npgsql: a canceled token throws before the command is sent.
    private static async Task<bool> CancellationAware(CancellationToken ct)
    {
        await Task.Yield();
        ct.ThrowIfCancellationRequested();
        return true;
    }

    [Fact]
    public async Task Reachable_IsHealthy()
    {
        var check = new DatabaseHealthCheck(CancellationAware);

        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(Context)).Status);
    }

    [Fact]
    public async Task NotReachable_IsUnhealthy()
    {
        var check = new DatabaseHealthCheck(_ => Task.FromResult(false));

        Assert.Equal(HealthStatus.Unhealthy, (await check.CheckHealthAsync(Context)).Status);
    }

    [Fact]
    public async Task Failure_IsUnhealthy_WithException()
    {
        var check = new DatabaseHealthCheck(_ => throw new InvalidOperationException("boom"));

        var result = await check.CheckHealthAsync(Context);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.IsType<InvalidOperationException>(result.Exception);
    }

    [Fact]
    public async Task CallerCanceled_PropagatesCancellation_InsteadOfUnhealthy()
    {
        // A reverse proxy that reloads its config hangs up on its in-flight /ready probe: not a database failure.
        var check = new DatabaseHealthCheck(CancellationAware);
        using var caller = new CancellationTokenSource();
        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => check.CheckHealthAsync(Context, caller.Token));
    }

    [Fact]
    public async Task SlowDatabase_IsUnhealthy_AfterOwnTimeout()
    {
        var check = new DatabaseHealthCheck(async ct =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return true;
        });
        using var caller = new CancellationTokenSource();

        var started = DateTime.UtcNow;
        var result = await check.CheckHealthAsync(Context, caller.Token);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.IsAssignableFrom<OperationCanceledException>(result.Exception);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(3), "the check must answer within the proxy's 3 s probe budget");
    }
}

public sealed class DatabaseHealthCheckSetupTests
{
    [Fact]
    public async Task Registration_ResolvesTheCheckAgainstTheDbContext()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<AgoraDbContext>(o => o.UseSqlite(connection));
        services.AddAgoraDatabaseHealthCheck();
        await using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>()
            .CheckHealthAsync(r => r.Tags.Contains(DatabaseHealthCheck.ReadyTag));

        Assert.Equal(HealthStatus.Healthy, report.Entries["database"].Status);
    }
}
