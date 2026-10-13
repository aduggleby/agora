using Agora.Web.Services;
using Microsoft.AspNetCore.Http;

namespace Agora.Application.Tests;

public sealed class PublicBaseUrlResolverTests
{
    [Fact]
    public void Configured_origin_wins_over_the_request_host()
    {
        var resolver = new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: true);

        Assert.Equal("https://files.example.com", resolver.Resolve(Request("http", "attacker.example")));
    }

    [Fact]
    public void Request_host_is_used_only_where_startup_allowed_it()
    {
        var allowed = new PublicBaseUrlResolver(null, allowRequestHostFallback: true);
        Assert.Equal("http://localhost:18080", allowed.Resolve(Request("http", "localhost:18080")));

        var production = new PublicBaseUrlResolver(null, allowRequestHostFallback: false);
        Assert.Throws<InvalidOperationException>(() => production.Resolve(Request("http", "localhost:18080")));
    }

    private static HttpRequest Request(string scheme, string host)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Host = new HostString(host);
        return context.Request;
    }
}
