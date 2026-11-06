using System.Net;
using System.Net.Sockets;

namespace Agora.Application.Utilities;

/// <summary>
/// The key every per-client-address limit and lockout uses. An IPv4 address (also when IPv4-mapped into IPv6) is
/// its own key; an IPv6 address is grouped by its /64 prefix, because a single client usually controls a whole /64
/// and could otherwise rotate addresses to escape per-address limits. Only for keys: logs and stored download
/// events keep the full address.
/// </summary>
public static class ClientAddresses
{
    public const string Unknown = "unknown";

    public static string PartitionKey(IPAddress? address)
    {
        if (address is null)
        {
            return Unknown;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return address.ToString();
        }

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return $"{new IPAddress(bytes)}/64";
    }

    /// <summary>
    /// The same key for an address that arrives as text. Text that is not an address (for example "unknown") is
    /// kept, trimmed and lower-cased, so it still names one bucket.
    /// </summary>
    public static string PartitionKey(string? address)
    {
        var text = (address ?? string.Empty).Trim();
        if (text.Length == 0)
        {
            return Unknown;
        }

        return IPAddress.TryParse(text, out var parsed) ? PartitionKey(parsed) : text.ToLowerInvariant();
    }
}
