using System.Net;

namespace Agora.Application.Utilities;

/// <summary>
/// Reverse proxies whose <c>X-Forwarded-*</c> headers are honoured (<c>Agora:TrustedProxies</c>,
/// env <c>Agora__TrustedProxies</c>): a comma, semicolon or whitespace separated list of IP addresses and CIDR
/// networks. Loopback is always trusted by the forwarded-headers middleware defaults and is not listed here.
/// </summary>
public sealed record TrustedProxies(IReadOnlyList<IPAddress> Addresses, IReadOnlyList<IPNetwork> Networks)
{
    public const string Key = "Agora:TrustedProxies";

    private static readonly char[] Separators = [',', ';', ' ', '\t', '\r', '\n'];

    public static TrustedProxies None { get; } = new([], []);

    public bool IsEmpty => Addresses.Count == 0 && Networks.Count == 0;

    /// <summary>
    /// Parses the setting. Empty means no proxies beyond loopback.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when any entry is neither an IP address nor a CIDR network.</exception>
    public static TrustedProxies Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return None;
        }

        var addresses = new List<IPAddress>();
        var networks = new List<IPNetwork>();
        foreach (var entry in value.Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (entry.Contains('/'))
            {
                if (!IPNetwork.TryParse(entry, out var network))
                {
                    throw Invalid(entry);
                }

                networks.Add(network);
                continue;
            }

            if (!IPAddress.TryParse(entry, out var address))
            {
                throw Invalid(entry);
            }

            addresses.Add(address);
        }

        return new TrustedProxies(addresses, networks);
    }

    private static InvalidOperationException Invalid(string entry) => new(
        $"Invalid entry '{entry}' in {Key} (env Agora__TrustedProxies). " +
        "Use IP addresses and CIDR networks separated by commas, for example '10.0.0.5,172.28.0.0/16'.");
}
