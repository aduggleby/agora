using System.Net;
using System.Text.Json;
using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;

namespace Agora.Application.Tests;

public sealed class PasswordHashingGateTests
{
    /// <summary>Upper bound for every wait in this class, so a regression fails instead of hanging the suite.</summary>
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    [Fact]
    public void Zero_slots_means_one_per_processor()
    {
        using var gate = new PasswordHashingGate(0);
        Assert.Equal(Environment.ProcessorCount, gate.MaxConcurrent);
        using var configured = new PasswordHashingGate(3);
        Assert.Equal(3, configured.MaxConcurrent);
    }

    [Fact]
    public async Task A_caller_that_finds_every_slot_busy_gives_up_after_the_wait()
    {
        using var gate = new PasswordHashingGate(1, TimeSpan.FromMilliseconds(100));
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        // The holder blocks inside the gate (its work is synchronous, like PBKDF2) on a dedicated thread, never a
        // pool thread, and with a bounded wait; the finally releases it whatever the assertions do.
        var holder = Task.Factory.StartNew(
            () => gate.RunAsync(() => { entered.TrySetResult(); release.Wait(Bound); return 0; }, CancellationToken.None),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default).Unwrap();
        try
        {
            await entered.Task.WaitAsync(Bound);
            await Assert.ThrowsAsync<PasswordHashingBusyException>(() => gate.VerifyAsync("password", "v2$1$AAAA$AAAA", CancellationToken.None).WaitAsync(Bound));
        }
        finally
        {
            release.Set();
            await holder.WaitAsync(Bound);
        }

        // The slot is free again: work runs.
        Assert.Equal(42, await gate.RunAsync(() => 42, CancellationToken.None).WaitAsync(Bound));
    }

    [Fact]
    public async Task Concurrency_never_exceeds_the_slot_count()
    {
        using var gate = new PasswordHashingGate(2, TimeSpan.FromSeconds(30));
        var current = 0;
        var peak = 0;
        var tasks = Enumerable.Range(0, 8).Select(_ => Task.Run(() => gate.RunAsync(() =>
        {
            var now = Interlocked.Increment(ref current);
            InterlockedMax(ref peak, now);
            Thread.Sleep(20);
            Interlocked.Decrement(ref current);
            return 0;
        }, CancellationToken.None)));
        await Task.WhenAll(tasks).WaitAsync(Bound);
        Assert.InRange(peak, 1, 2);
    }

    [Theory]
    [InlineData("/login", "/login?msg=")]
    [InlineData("/register", "/register?msg=")]
    public async Task Busy_form_posts_go_back_to_their_page_with_a_message(string path, string expectedPrefix)
    {
        await using var app = await StartAsync();
        var context = await SendAsync(app, ctx =>
        {
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = path;
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            ctx.Request.Body = new MemoryStream("email=a%40b.c"u8.ToArray());
        });

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        var location = context.Response.Headers.Location.ToString();
        Assert.StartsWith(expectedPrefix, location, StringComparison.Ordinal);
        Assert.Contains(Uri.EscapeDataString(PasswordHashingBusyException.BusyMessage), location, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/s/Abc123xyz/download")]
    [InlineData("/s/Abc123xyz/unlock")]
    public async Task Busy_share_password_posts_go_back_to_the_share_page(string path)
    {
        await using var app = await StartAsync();
        var context = await SendAsync(app, ctx =>
        {
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = path;
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            ctx.Request.Body = new MemoryStream("downloadPassword=x"u8.ToArray());
        });

        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Equal("/s/Abc123xyz?downloadError=busy", context.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task Busy_api_and_other_requests_get_503_with_retry_after()
    {
        await using var app = await StartAsync();

        var api = await SendAsync(app, ctx =>
        {
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = "/api/thing";
        });
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, api.Response.StatusCode);
        Assert.Equal("5", api.Response.Headers.RetryAfter.ToString());
        using var json = await JsonDocument.ParseAsync(api.Response.Body).WaitAsync(Bound);
        Assert.Equal(PasswordHashingBusyException.BusyMessage, json.RootElement.GetProperty("error").GetString());

        var other = await SendAsync(app, ctx =>
        {
            ctx.Request.Method = HttpMethods.Post;
            ctx.Request.Path = "/other";
        });
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, other.Response.StatusCode);
        Assert.Equal("5", other.Response.Headers.RetryAfter.ToString());
    }

    private static Task<HttpContext> SendAsync(WebApplication app, Action<HttpContext> configure) =>
        app.GetTestServer().SendAsync(configure).WaitAsync(Bound);

    private static async Task<WebApplication> StartAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.UsePasswordHashingBusyHandling();
        // What the gate throws when every slot stays busy (covered against the real gate above); no thread is parked.
        RequestDelegate busy = _ => throw new PasswordHashingBusyException();
        app.MapPost("/login", busy);
        app.MapPost("/register", busy);
        app.MapPost("/api/thing", busy);
        app.MapPost("/s/{token}/download", busy);
        app.MapPost("/s/{token}/unlock", busy);
        app.MapPost("/other", busy);
        await app.StartAsync().WaitAsync(Bound);
        return app;
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int seen;
        while (value > (seen = Volatile.Read(ref target)) && Interlocked.CompareExchange(ref target, value, seen) != seen)
        {
        }
    }
}
