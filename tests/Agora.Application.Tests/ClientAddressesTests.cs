using System.Net;
using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class ClientAddressesTests
{
    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", "203.0.113.7")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2::1", "2001:db8:1:2::/64")]
    [InlineData("2001:DB8:1:2:ffff::", "2001:db8:1:2::/64")]
    [InlineData("fe80::1%3", "fe80::/64")]
    [InlineData("::1", "::/64")]
    public void Partition_key_is_the_IPv4_address_or_the_IPv6_64(string address, string expected)
    {
        Assert.Equal(expected, ClientAddresses.PartitionKey(IPAddress.Parse(address)));
        Assert.Equal(expected, ClientAddresses.PartitionKey(address));
    }

    [Fact]
    public void Missing_or_unparsable_addresses_keep_a_stable_key()
    {
        Assert.Equal(ClientAddresses.Unknown, ClientAddresses.PartitionKey((IPAddress?)null));
        Assert.Equal(ClientAddresses.Unknown, ClientAddresses.PartitionKey((string?)null));
        Assert.Equal(ClientAddresses.Unknown, ClientAddresses.PartitionKey("  "));
        Assert.Equal("unknown", ClientAddresses.PartitionKey(" Unknown "));
    }
}
