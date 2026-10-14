using Agora.Web.Startup;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Time.Testing;

namespace Agora.Application.Tests;

public sealed class ObjectStoreHealthCheckTests
{
    private static readonly HealthCheckContext Context = new();

    private static Task Fail(CancellationToken _) => throw new InvalidOperationException("boom");

    private static Task Hang(CancellationToken ct) => Task.Delay(Timeout.InfiniteTimeSpan, ct);

    [Fact]
    public async Task Success_IsHealthy_AndCachedFor30Seconds()
    {
        var time = new FakeTimeProvider();
        var calls = 0;
        var check = new ObjectStoreHealthCheck(_ => { calls++; return Task.CompletedTask; }, time);

        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(Context)).Status);
        time.Advance(TimeSpan.FromSeconds(29));
        Assert.Equal(HealthStatus.Healthy, (await check.CheckHealthAsync(Context)).Status);
        Assert.Equal(1, calls);

        time.Advance(TimeSpan.FromSeconds(2));
        await check.CheckHealthAsync(Context);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task FailureWithinGrace_IsDegraded_WithAgeAndException()
    {
        var time = new FakeTimeProvider();
        var fail = false;
        var check = new ObjectStoreHealthCheck(ct => fail ? Fail(ct) : Task.CompletedTask, time);
        await check.CheckHealthAsync(Context);

        fail = true;
        time.Advance(TimeSpan.FromSeconds(90));
        var result = await check.CheckHealthAsync(Context);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("90 s ago", result.Description);
        Assert.IsType<InvalidOperationException>(result.Exception);
    }

    [Fact]
    public async Task FailureAfterGrace_IsUnhealthy()
    {
        var time = new FakeTimeProvider();
        var fail = false;
        var check = new ObjectStoreHealthCheck(ct => fail ? Fail(ct) : Task.CompletedTask, time);
        await check.CheckHealthAsync(Context);

        fail = true;
        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(HealthStatus.Unhealthy, (await check.CheckHealthAsync(Context)).Status);
    }

    [Fact]
    public async Task NeverHealthyFailure_IsUnhealthy()
    {
        var check = new ObjectStoreHealthCheck(Fail, new FakeTimeProvider());
        Assert.Equal(HealthStatus.Unhealthy, (await check.CheckHealthAsync(Context)).Status);
    }

    [Fact]
    public async Task SlowPing_TimesOutAfter2Seconds_AndFollowsGraceRule()
    {
        var time = new FakeTimeProvider();
        var slow = false;
        var check = new ObjectStoreHealthCheck(ct => slow ? Hang(ct) : Task.CompletedTask, time);

        // Never healthy: timeout is Unhealthy.
        slow = true;
        var first = check.CheckHealthAsync(Context);
        time.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(HealthStatus.Unhealthy, (await first).Status);

        // After a success, a timeout inside the grace period is Degraded.
        slow = false;
        await check.CheckHealthAsync(Context);
        slow = true;
        time.Advance(TimeSpan.FromSeconds(31));
        var pending = check.CheckHealthAsync(Context);
        Assert.False(pending.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(2));
        var result = await pending;

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.IsAssignableFrom<OperationCanceledException>(result.Exception);
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        var check = new ObjectStoreHealthCheck(Hang, new FakeTimeProvider());
        using var cts = new CancellationTokenSource();
        var pending = check.CheckHealthAsync(Context, cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
    }
}
