using Agora.Web.Pages;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// The forgot-password, reset-password, confirm-email-required and emailed-link confirmation pages are Razor page
/// handlers, not minimal endpoints, so they only share the per-IP "AuthEndpoints" limiter if the attribute on the PageModel ends up in
/// the page's endpoint metadata. This checks the real routing table of the Agora.Web assembly.
/// </summary>
public sealed class AuthPageRateLimitTests
{
    [Theory]
    [InlineData("forgot-password")]
    [InlineData("reset-password")]
    [InlineData("confirm-email-required")]
    [InlineData("auth/confirm-email")]
    [InlineData("auth/confirm-email-change")]
    [InlineData("auth/confirm-password-change")]
    public async Task Auth_pages_carry_the_AuthEndpoints_rate_limit_policy(string route)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddRazorPages().AddApplicationPart(typeof(ForgotPasswordModel).Assembly);
        await using var app = builder.Build();
        app.MapRazorPages();
        await app.StartAsync();

        var endpoints = app.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => string.Equals(e.RoutePattern.RawText?.TrimStart('/'), route, StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(endpoints);
        Assert.All(endpoints, endpoint =>
        {
            var policy = endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>();
            Assert.NotNull(policy);
            Assert.Equal("AuthEndpoints", policy.PolicyName);
        });
    }

    [Fact]
    public void Login_and_register_pages_are_not_limited_themselves()
    {
        // Their POSTs are minimal endpoints that already use the policy; the GET pages stay free.
        Assert.Null(Attribute.GetCustomAttribute(typeof(LoginModel), typeof(EnableRateLimitingAttribute)));
        Assert.Null(Attribute.GetCustomAttribute(typeof(RegisterModel), typeof(EnableRateLimitingAttribute)));
    }
}
