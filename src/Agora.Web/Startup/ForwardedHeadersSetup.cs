using System.Net;
using Agora.Application.Utilities;
using Microsoft.AspNetCore.HttpOverrides;

namespace Agora.Web.Startup;

/// <summary>
/// Configures which peers may rewrite RemoteIpAddress, Scheme and Host through <c>X-Forwarded-*</c>: loopback plus
/// <c>Agora:TrustedProxies</c>, nothing else. The lists are reset first so the outcome does not depend on earlier
/// callbacks (the framework's <c>ASPNETCORE_FORWARDEDHEADERS_ENABLED</c> filter clears them to trust everyone).
/// </summary>
public static class ForwardedHeadersSetup
{
    public static void Configure(ForwardedHeadersOptions options, TrustedProxies trustedProxies)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor
            | ForwardedHeaders.XForwardedProto
            | ForwardedHeaders.XForwardedHost;

        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        options.KnownProxies.Add(IPAddress.IPv6Loopback);
        options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Loopback, 8));
        options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.IPv6Loopback, 128));

        foreach (var address in trustedProxies.Addresses)
        {
            options.KnownProxies.Add(address);
        }

        foreach (var network in trustedProxies.Networks)
        {
            options.KnownIPNetworks.Add(network);
        }
    }
}
