using Agora.Application.Models;
using Agora.Web.Endpoints;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// Runs <see cref="SecurityHeaders.UseAgoraSecurityHeaders"/> (what Program.cs uses) on a TestServer and checks which
/// headers land on HTML pages, user-content responses, the Hangfire dashboard and plain HTTP requests.
/// </summary>
public sealed class SecurityHeadersHostTests
{
    private const string NonceEcho = "X-Seen-Nonce";

    [Fact]
    public async Task Html_page_gets_the_fixed_headers_and_a_report_only_policy_with_the_page_nonce()
    {
        await using var host = await StartAsync(enabled: true);

        var response = await host.GetAsync("/page", https: true);

        Assert.Equal("nosniff", response.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal("SAMEORIGIN", response.Headers["X-Frame-Options"].ToString());
        Assert.Equal("strict-origin-when-cross-origin", response.Headers["Referrer-Policy"].ToString());
        Assert.Equal("camera=(), microphone=(), geolocation=()", response.Headers["Permissions-Policy"].ToString());
        Assert.Equal(SecurityHeaders.HstsValue, response.Headers["Strict-Transport-Security"].ToString());

        var nonce = response.Headers[NonceEcho].ToString();
        Assert.False(string.IsNullOrWhiteSpace(nonce));
        var policy = response.Headers[SecurityHeaders.ReportOnlyHeaderName].ToString();
        Assert.Equal(SecurityHeaders.ReportOnlyPolicy(nonce), policy);
        Assert.Contains($"script-src 'self' 'nonce-{nonce}'", policy, StringComparison.Ordinal);
        Assert.False(response.Headers.ContainsKey("Content-Security-Policy"));
    }

    [Fact]
    public async Task Nonce_differs_per_request()
    {
        await using var host = await StartAsync(enabled: true);

        var first = (await host.GetAsync("/page", https: true)).Headers[NonceEcho].ToString();
        var second = (await host.GetAsync("/page", https: true)).Headers[NonceEcho].ToString();

        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task Hsts_is_sent_only_on_https()
    {
        await using var host = await StartAsync(enabled: true);

        var http = await host.GetAsync("/page", https: false);
        var https = await host.GetAsync("/page", https: true);

        Assert.False(http.Headers.ContainsKey("Strict-Transport-Security"));
        Assert.Equal(SecurityHeaders.HstsValue, https.Headers["Strict-Transport-Security"].ToString());
        Assert.Equal("nosniff", http.Headers["X-Content-Type-Options"].ToString());
    }

    [Fact]
    public async Task User_content_keeps_its_enforced_policy_and_gets_no_report_only_policy()
    {
        await using var host = await StartAsync(enabled: true);

        var response = await host.GetAsync("/user-content", https: true);

        Assert.Equal(ObjectResults.UserContentCsp, response.Headers["Content-Security-Policy"].ToString());
        Assert.False(response.Headers.ContainsKey(SecurityHeaders.ReportOnlyHeaderName));
        Assert.Equal("nosniff", response.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal("SAMEORIGIN", response.Headers["X-Frame-Options"].ToString());
    }

    [Fact]
    public async Task Headers_already_set_by_the_endpoint_are_not_overridden()
    {
        await using var host = await StartAsync(enabled: true);

        var response = await host.GetAsync("/preset", https: true);

        Assert.Equal("DENY", response.Headers["X-Frame-Options"].ToString());
        Assert.Equal("no-referrer", response.Headers["Referrer-Policy"].ToString());
        Assert.Equal("default-src 'none'", response.Headers["Content-Security-Policy"].ToString());
        Assert.False(response.Headers.ContainsKey(SecurityHeaders.ReportOnlyHeaderName));
    }

    [Fact]
    public async Task Non_html_responses_and_the_hangfire_dashboard_get_no_report_only_policy()
    {
        await using var host = await StartAsync(enabled: true);

        var json = await host.GetAsync("/json", https: true);
        var hangfire = await host.GetAsync("/hangfire/jobs", https: true);

        Assert.False(json.Headers.ContainsKey(SecurityHeaders.ReportOnlyHeaderName));
        Assert.Equal("nosniff", json.Headers["X-Content-Type-Options"].ToString());
        Assert.False(hangfire.Headers.ContainsKey(SecurityHeaders.ReportOnlyHeaderName));
        Assert.Equal("SAMEORIGIN", hangfire.Headers["X-Frame-Options"].ToString());
    }

    [Fact]
    public async Task Unhandled_exception_becomes_a_500_that_still_carries_the_headers()
    {
        await using var host = await StartAsync(enabled: true);

        var response = await host.GetAsync("/throw", https: true, expectedStatus: StatusCodes.Status500InternalServerError);

        Assert.Equal("nosniff", response.Headers["X-Content-Type-Options"].ToString());
        Assert.Equal("SAMEORIGIN", response.Headers["X-Frame-Options"].ToString());
        Assert.Equal("strict-origin-when-cross-origin", response.Headers["Referrer-Policy"].ToString());
        Assert.Equal("camera=(), microphone=(), geolocation=()", response.Headers["Permissions-Policy"].ToString());
        Assert.Equal(SecurityHeaders.HstsValue, response.Headers["Strict-Transport-Security"].ToString());
        Assert.StartsWith("text/plain", response.Headers.ContentType.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Switch_turns_the_middleware_off()
    {
        await using var host = await StartAsync(enabled: false);

        var response = await host.GetAsync("/page", https: true);

        Assert.False(response.Headers.ContainsKey("X-Content-Type-Options"));
        Assert.False(response.Headers.ContainsKey("X-Frame-Options"));
        Assert.False(response.Headers.ContainsKey("Referrer-Policy"));
        Assert.False(response.Headers.ContainsKey("Permissions-Policy"));
        Assert.False(response.Headers.ContainsKey("Strict-Transport-Security"));
        Assert.False(response.Headers.ContainsKey(SecurityHeaders.ReportOnlyHeaderName));
        Assert.Equal(string.Empty, response.Headers[NonceEcho].ToString());
    }

    private static async Task<Host> StartAsync(bool enabled)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.Configure<AgoraOptions>(options => options.SecurityHeaders.Enabled = enabled);

        var app = builder.Build();
        app.UseAgoraSecurityHeaders();
        app.UseAgoraExceptionHandler();
        app.MapGet("/throw", IResult () => throw new InvalidOperationException("boom"));
        app.MapGet("/page", (HttpContext context) =>
        {
            context.Response.Headers[NonceEcho] = context.Items[SecurityHeaders.NonceItemKey] as string ?? string.Empty;
            return Results.Content("<!doctype html><html></html>", "text/html; charset=utf-8");
        });
        app.MapGet("/hangfire/jobs", () => Results.Content("<!doctype html><html></html>", "text/html; charset=utf-8"));
        app.MapGet("/json", () => Results.Json(new { ok = true }));
        app.MapGet("/user-content", (HttpContext context) =>
        {
            ObjectResults.ApplyUserContentHeaders(context.Response);
            return Results.Bytes([1, 2, 3], "image/png");
        });
        app.MapGet("/preset", (HttpContext context) =>
        {
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'";
            return Results.Content("<!doctype html><html></html>", "text/html; charset=utf-8");
        });
        await app.StartAsync();
        return new Host(app);
    }

    private sealed class Host(WebApplication app) : IAsyncDisposable
    {
        public async Task<HttpResponse> GetAsync(string path, bool https, int expectedStatus = StatusCodes.Status200OK)
        {
            var context = await app.GetTestServer().SendAsync(ctx =>
            {
                ctx.Request.Method = HttpMethods.Get;
                ctx.Request.Path = path;
                ctx.Request.Scheme = https ? "https" : "http";
                ctx.Request.Host = new HostString("agora.test");
            });

            Assert.Equal(expectedStatus, context.Response.StatusCode);
            return context.Response;
        }

        public ValueTask DisposeAsync() => app.DisposeAsync();
    }
}
