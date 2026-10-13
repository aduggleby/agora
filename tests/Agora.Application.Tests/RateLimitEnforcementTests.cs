using System.Net;
using Agora.Application.Models;
using Agora.Web.Pages;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// Runs the real rate limiter registration (<see cref="RateLimitSetup"/>, non-E2E) against the real Razor Pages of
/// Agora.Web and checks the limits bite per client IP.
/// </summary>
public sealed class RateLimitEnforcementTests
{
    [Fact]
    public async Task Auth_page_posts_from_one_ip_get_429_after_ten_in_a_minute()
    {
        await using var app = await StartAsync(new AgoraRateLimitOptions());

        for (var i = 0; i < 10; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, await app.PostAsync("/forgot-password", peer: "203.0.113.9"));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await app.PostAsync("/forgot-password", peer: "203.0.113.9"));
        // The same window also covers the other auth pages and the limit is per client, not global.
        Assert.Equal(HttpStatusCode.TooManyRequests, await app.PostAsync("/reset-password", peer: "203.0.113.9"));
        Assert.NotEqual(HttpStatusCode.TooManyRequests, await app.PostAsync("/forgot-password", peer: "203.0.113.10"));
    }

    [Fact]
    public async Task Anonymous_requests_are_limited_per_ip_except_health_endpoints()
    {
        await using var app = await StartAsync(new AgoraRateLimitOptions { AnonymousPerMinute = 3 });

        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.OK, await app.GetAsync("/anything", peer: "203.0.113.9"));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, await app.GetAsync("/anything", peer: "203.0.113.9"));
        Assert.Equal(HttpStatusCode.OK, await app.GetAsync("/anything", peer: "203.0.113.10"));
        Assert.Equal(HttpStatusCode.OK, await app.GetAsync("/live", peer: "203.0.113.9"));
    }

    private static async Task<Host> StartAsync(AgoraRateLimitOptions limits)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
        builder.Services.AddSingleton(new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: false));
        builder.Services.AddRateLimiter(options => RateLimitSetup.Configure(options, limits, isE2E: false));

        var app = builder.Build();
        app.UseRateLimiter();
        app.MapRazorPages();
        app.MapGet("/anything", () => Results.Ok());
        app.MapGet("/live", () => Results.Ok()).DisableRateLimiting();
        await app.StartAsync();
        return new Host(app);
    }

    private sealed class Host(WebApplication app) : IAsyncDisposable
    {
        public Task<HttpStatusCode> PostAsync(string path, string peer) => SendAsync(HttpMethods.Post, path, peer);

        public Task<HttpStatusCode> GetAsync(string path, string peer) => SendAsync(HttpMethods.Get, path, peer);

        private async Task<HttpStatusCode> SendAsync(string method, string path, string peer)
        {
            var context = await app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = method;
                ctx.Request.Path = path;
                ctx.Connection.RemoteIpAddress = IPAddress.Parse(peer);
                if (method == HttpMethods.Post)
                {
                    ctx.Request.ContentType = "application/x-www-form-urlencoded";
                    ctx.Request.Body = new MemoryStream("email=someone%40example.com"u8.ToArray());
                }
            });

            return (HttpStatusCode)context.Response.StatusCode;
        }

        public ValueTask DisposeAsync() => app.DisposeAsync();
    }
}
