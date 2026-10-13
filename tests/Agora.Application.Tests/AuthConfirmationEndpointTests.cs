using Agora.Infrastructure.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Application.Tests;

/// <summary>
/// The emailed confirmation links are GET endpoints mapped by <see cref="AuthConfirmationEndpoints"/>; each must carry
/// the per-IP "AuthEndpoints" limiter like the sign-in and registration handlers.
/// </summary>
public sealed class AuthConfirmationEndpointTests
{
    [Theory]
    [InlineData("/auth/confirm-email")]
    [InlineData("/auth/confirm-email-change")]
    [InlineData("/auth/confirm-password-change")]
    public async Task Confirmation_link_endpoints_carry_the_AuthEndpoints_rate_limit_policy(string route)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        // Registered so the handlers' AuthService parameter is inferred as a service, as in Program.cs.
        builder.Services.AddScoped<AuthService>();
        await using var app = builder.Build();
        app.MapAuthConfirmationEndpoints();
        await app.StartAsync();

        var endpoints = app.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(e => string.Equals(e.RoutePattern.RawText, route, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var endpoint = Assert.Single(endpoints);
        Assert.Contains("GET", endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods);
        var policy = endpoint.Metadata.GetMetadata<EnableRateLimitingAttribute>();
        Assert.NotNull(policy);
        Assert.Equal(RateLimitSetup.AuthEndpoints, policy.PolicyName);
    }
}
