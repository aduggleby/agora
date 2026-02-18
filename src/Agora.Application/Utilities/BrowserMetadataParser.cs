using System.Text.Json;

namespace Agora.Application.Utilities;

public static class BrowserMetadataParser
{
    public static string ToJson(string userAgent)
    {
        var ua = userAgent ?? string.Empty;
        var browser = "Unknown";

        if (ua.Contains("Edg/", StringComparison.OrdinalIgnoreCase)) browser = "Edge";
        else if (ua.Contains("Chrome/", StringComparison.OrdinalIgnoreCase)) browser = "Chrome";
        else if (ua.Contains("Firefox/", StringComparison.OrdinalIgnoreCase)) browser = "Firefox";
        else if (ua.Contains("Safari/", StringComparison.OrdinalIgnoreCase)) browser = "Safari";

        var os = "Unknown";
        if (ua.Contains("Windows", StringComparison.OrdinalIgnoreCase)) os = "Windows";
        else if (ua.Contains("Mac OS", StringComparison.OrdinalIgnoreCase)) os = "macOS";
        else if (ua.Contains("Linux", StringComparison.OrdinalIgnoreCase)) os = "Linux";
        else if (ua.Contains("Android", StringComparison.OrdinalIgnoreCase)) os = "Android";
        else if (ua.Contains("iPhone", StringComparison.OrdinalIgnoreCase) || ua.Contains("iPad", StringComparison.OrdinalIgnoreCase)) os = "iOS";

        var device = ua.Contains("Mobile", StringComparison.OrdinalIgnoreCase) ? "Mobile" : "Desktop";

        return JsonSerializer.Serialize(new
        {
            browserFamily = browser,
            browserVersion = "unknown",
            osFamily = os,
            osVersion = "unknown",
            deviceType = device
        });
    }
}
