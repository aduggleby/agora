using System.Text.Json;
using Agora.Application.Utilities;
using Microsoft.Extensions.Logging;

namespace Agora.Infrastructure.Services;

public sealed class IpWhoIsDownloaderGeoLookup(
    HttpClient httpClient,
    ILogger<IpWhoIsDownloaderGeoLookup> logger) : IDownloaderGeoLookup
{
    public async Task<string> FormatForNotificationAsync(string ipAddress, CancellationToken cancellationToken)
    {
        var fallback = string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress.Trim();
        if (!IpAddressUtilities.TryNormalizeIp(ipAddress, out var normalizedIp))
        {
            return fallback;
        }

        if (!IpAddressUtilities.IsPublicRoutable(normalizedIp))
        {
            return normalizedIp;
        }

        try
        {
            var response = await httpClient.GetAsync($"{Uri.EscapeDataString(normalizedIp)}?fields=success,city,country", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return normalizedIp;
            }

            using var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken), cancellationToken: cancellationToken);
            var root = payload.RootElement;
            var success = root.TryGetProperty("success", out var successElement) && successElement.ValueKind == JsonValueKind.True;
            if (!success)
            {
                return normalizedIp;
            }

            var city = root.TryGetProperty("city", out var cityElement) ? cityElement.GetString()?.Trim() : null;
            var country = root.TryGetProperty("country", out var countryElement) ? countryElement.GetString()?.Trim() : null;
            if (string.IsNullOrWhiteSpace(city) || string.IsNullOrWhiteSpace(country))
            {
                return normalizedIp;
            }

            return $"{normalizedIp} ({city}, {country})";
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Geo lookup failed for downloader IP {IpAddress}", normalizedIp);
            return normalizedIp;
        }
    }
}
