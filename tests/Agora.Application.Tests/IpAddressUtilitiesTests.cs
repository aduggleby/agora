using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class IpAddressUtilitiesTests
{
    [Fact]
    public void ExtractFromForwardedFor_PrefersPublicAddress()
    {
        var header = "10.0.0.12, 198.51.100.7, 8.8.8.8";

        var result = IpAddressUtilities.ExtractFromForwardedFor(header, preferPublic: true);

        Assert.Equal("8.8.8.8", result);
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
