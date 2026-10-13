using System.Net;
using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class TrustedProxiesTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData(" , ; ")]
    public void Parse_EmptyMeansNoProxies(string? value)
    {
        var proxies = TrustedProxies.Parse(value);

        Assert.True(proxies.IsEmpty);
        Assert.Empty(proxies.Addresses);
        Assert.Empty(proxies.Networks);
    }

    [Fact]
    public void Parse_AcceptsAddressesAndNetworksWithAnySeparator()
    {
        var proxies = TrustedProxies.Parse("10.0.0.5, 172.28.0.0/16;fd00::/8\t2001:db8::1\n192.0.2.7");

        Assert.Equal(
            [IPAddress.Parse("10.0.0.5"), IPAddress.Parse("2001:db8::1"), IPAddress.Parse("192.0.2.7")],
            proxies.Addresses);
        Assert.Equal([IPNetwork.Parse("172.28.0.0/16"), IPNetwork.Parse("fd00::/8")], proxies.Networks);
    }

    [Fact]
    public void Parse_MasksHostBitsOfANetwork()
    {
        var proxies = TrustedProxies.Parse("172.28.4.2/16");

        Assert.Equal([IPNetwork.Parse("172.28.0.0/16")], proxies.Networks);
    }

    [Theory]
    [InlineData("proxy.example.com")]
    [InlineData("300.1.1.1")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.5/")]
    [InlineData("10.0.0.5,not-an-ip")]
    public void Parse_RejectsInvalidEntries(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => TrustedProxies.Parse(value));

        Assert.Contains("Agora__TrustedProxies", ex.Message, StringComparison.Ordinal);
        Assert.Contains(value.Split(',').Last(), ex.Message, StringComparison.Ordinal);
    }
}
