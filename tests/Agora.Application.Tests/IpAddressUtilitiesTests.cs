using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class IpAddressUtilitiesTests
{
    [Fact]
    public void TryNormalizeIp_MapsIpv4MappedIpv6ToIpv4()
    {
        var ok = IpAddressUtilities.TryNormalizeIp("::ffff:203.0.113.9", out var normalized);

        Assert.True(ok);
        Assert.Equal("203.0.113.9", normalized);
    }

    [Fact]
    public void TryNormalizeIp_StripsIpv4Port()
    {
        var ok = IpAddressUtilities.TryNormalizeIp("203.0.113.9:443", out var normalized);

        Assert.True(ok);
        Assert.Equal("203.0.113.9", normalized);
    }

    [Fact]
    public void IsPublicRoutable_RejectsPrivateAddress()
    {
        var isPublic = IpAddressUtilities.IsPublicRoutable("192.168.1.15");

        Assert.False(isPublic);
    }
}
