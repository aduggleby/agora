using System.Net;
using Agora.Application.Utilities;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// Runs the real forwarded-headers middleware through <see cref="ForwardedHeadersSetup"/> (what Program.cs uses)
/// and checks which peers may rewrite RemoteIpAddress, Scheme and Host.
/// </summary>
public sealed class ForwardedHeadersHostTests
{
    private const string ClientIp = "198.51.100.7";
    private const string ForwardedHost = "files.example.com";

    [Fact]
    public async Task Untrusted_peer_cannot_rewrite_address_scheme_or_host()
    {
        await using var host = await StartAsync("10.0.0.5");

        var seen = await host.SendForwardedAsync(peer: "203.0.113.9");

        Assert.Equal("203.0.113.9", seen.RemoteIp);
        Assert.Equal("http", seen.Scheme);
        Assert.Equal("agora.test", seen.Host);
    }

    [Fact]
    public async Task Trusted_address_rewrites_address_scheme_and_host()
    {
        await using var host = await StartAsync("10.0.0.5");

        var seen = await host.SendForwardedAsync(peer: "10.0.0.5");

        Assert.Equal(ClientIp, seen.RemoteIp);
        Assert.Equal("https", seen.Scheme);
        Assert.Equal(ForwardedHost, seen.Host);
    }

    [Fact]
    public async Task Trusted_network_covers_every_address_in_it_including_ipv4_mapped_ipv6()
    {
        await using var host = await StartAsync("172.28.0.0/16");

        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "172.28.4.2")).RemoteIp);
        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "::ffff:172.28.4.2")).RemoteIp);
        Assert.Equal("172.29.0.1", (await host.SendForwardedAsync(peer: "172.29.0.1")).RemoteIp);
    }

    [Fact]
    public async Task Empty_setting_trusts_loopback_only()
    {
        await using var host = await StartAsync(null);

        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "127.0.0.1")).RemoteIp);
        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "::1")).RemoteIp);
        Assert.Equal("10.0.0.5", (await host.SendForwardedAsync(peer: "10.0.0.5")).RemoteIp);
    }

    [Fact]
    public async Task Lists_cleared_by_an_earlier_callback_do_not_reinstate_trust_all()
    {
        // ASPNETCORE_FORWARDEDHEADERS_ENABLED=true registers a startup filter that clears both lists (trust everyone).
        // Our setup resets them, so the outcome is the same whatever ran before.
        await using var host = await StartAsync("10.0.0.5", preClearLists: true);

        Assert.Equal("203.0.113.9", (await host.SendForwardedAsync(peer: "203.0.113.9")).RemoteIp);
        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "10.0.0.5")).RemoteIp);
        Assert.Equal(ClientIp, (await host.SendForwardedAsync(peer: "127.0.0.1")).RemoteIp);
    }

    private static async Task<Host> StartAsync(string? trustedProxiesSetting, bool preClearLists = false)
    {
        var trustedProxies = TrustedProxies.Parse(trustedProxiesSetting);
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        if (preClearLists)
        {
            builder.Services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.KnownProxies.Clear();
                options.KnownIPNetworks.Clear();
            });
        }

        builder.Services.Configure<ForwardedHeadersOptions>(options => ForwardedHeadersSetup.Configure(options, trustedProxies));

        var app = builder.Build();
        app.UseForwardedHeaders();
        app.MapGet("/ip", (HttpContext context) =>
        {
            context.Response.Headers["X-Seen-Ip"] = context.Connection.RemoteIpAddress?.ToString() ?? "none";
            context.Response.Headers["X-Seen-Scheme"] = context.Request.Scheme;
            context.Response.Headers["X-Seen-Host"] = context.Request.Host.Value;
            return Results.Ok();
        });
        await app.StartAsync();
        return new Host(app);
    }

    private sealed record Seen(string RemoteIp, string Scheme, string Host);

    private sealed class Host(WebApplication app) : IAsyncDisposable
    {
        public async Task<Seen> SendForwardedAsync(string peer)
        {
            var context = await app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = "/ip";
                ctx.Request.Scheme = "http";
                ctx.Request.Host = new HostString("agora.test");
                ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
                ctx.Request.Headers["X-Forwarded-For"] = ClientIp;
                ctx.Request.Headers["X-Forwarded-Proto"] = "https";
                ctx.Request.Headers["X-Forwarded-Host"] = ForwardedHost;
            });

            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
            return new Seen(
                context.Response.Headers["X-Seen-Ip"].ToString(),
                context.Response.Headers["X-Seen-Scheme"].ToString(),
                context.Response.Headers["X-Seen-Host"].ToString());
        }

        public ValueTask DisposeAsync() => app.DisposeAsync();
    }
}
