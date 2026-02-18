using System.Net;

namespace Agora.Application.Utilities;

public static class IpAddressUtilities
{
    public static bool TryNormalizeIp(string? value, out string normalizedIp)
    {
        normalizedIp = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (!TryParseIpAddress(value, out var ipAddress))
        {
            return false;
        }

        normalizedIp = Normalize(ipAddress);
        return true;
    }

    public static string? ExtractFromForwardedFor(string? forwardedFor, bool preferPublic)
    {
        if (string.IsNullOrWhiteSpace(forwardedFor))
        {
            return null;
        }

        string? firstValid = null;
        foreach (var token in forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParseIpAddress(token, out var ipAddress))
            {
                continue;
            }

            var normalized = Normalize(ipAddress);
            firstValid ??= normalized;
            if (!preferPublic || IsPublicRoutable(ipAddress))
            {
                return normalized;
            }
        }

        return firstValid;
    }

    public static bool IsPublicRoutable(string ipAddress)
    {
        if (!TryParseIpAddress(ipAddress, out var parsed))
        {
            return false;
        }

        return IsPublicRoutable(parsed);
    }

    private static bool IsPublicRoutable(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            var b0 = bytes[0];
            var b1 = bytes[1];
            var b2 = bytes[2];

            if (b0 == 10 || b0 == 127 || b0 == 0)
            {
                return false;
            }

            if (b0 == 169 && b1 == 254)
            {
                return false;
            }

            if (b0 == 172 && b1 >= 16 && b1 <= 31)
            {
                return false;
            }

            if (b0 == 192 && b1 == 168)
            {
                return false;
            }

            if (b0 == 100 && b1 >= 64 && b1 <= 127)
            {
                return false;
            }

            if (b0 == 198 && (b1 == 18 || b1 == 19))
            {
                return false;
            }

            if (b0 == 192 && b1 == 0 && b2 == 2)
            {
                return false;
            }

            if (b0 == 198 && b1 == 51 && b2 == 100)
            {
                return false;
            }

            if (b0 == 203 && b1 == 0 && b2 == 113)
            {
                return false;
            }

            if (b0 >= 224)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (address.Equals(IPAddress.IPv6Loopback) || address.Equals(IPAddress.IPv6None))
            {
                return false;
            }

            if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal)
            {
                return false;
            }

            var bytes = address.GetAddressBytes();
            if ((bytes[0] & 0xFE) == 0xFC)
            {
                return false;
            }

            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8)
            {
                return false;
            }

            return true;
        }

        return false;
    }

    private static bool TryParseIpAddress(string value, out IPAddress ipAddress)
    {
        ipAddress = IPAddress.None;
        var token = (value ?? string.Empty).Trim().Trim('"');
        if (token.Length == 0)
        {
            return false;
        }

        var zoneIndex = token.IndexOf('%');
        if (zoneIndex >= 0)
        {
            token = token[..zoneIndex];
        }

        if (token.StartsWith("[", StringComparison.Ordinal))
        {
            var bracketEnd = token.IndexOf(']');
            if (bracketEnd <= 1)
            {
                return false;
            }

            token = token[1..bracketEnd];
        }
        else
        {
            var colonCount = token.Count(static c => c == ':');
            if (colonCount == 1 && token.Contains('.'))
            {
                var lastColon = token.LastIndexOf(':');
                if (lastColon > 0)
                {
                    token = token[..lastColon];
                }
            }
        }

        if (!IPAddress.TryParse(token, out var parsed) || parsed is null)
        {
            return false;
        }

        ipAddress = parsed;
        return true;
    }

    private static string Normalize(IPAddress ipAddress)
    {
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            return ipAddress.MapToIPv4().ToString();
        }

        return ipAddress.ToString();
    }
}
