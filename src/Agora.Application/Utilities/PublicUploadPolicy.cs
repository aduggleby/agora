using Agora.Application.Models;

namespace Agora.Application.Utilities;

/// <summary>
/// Pure decisions for received (anonymous) uploads: which expiry a received share gets and whether the owner's
/// daily quota admits another one.
/// </summary>
public static class PublicUploadPolicy
{
    public sealed record ReceivedShareExpiry(string Mode, DateTime? ExpiresAtUtc);

    /// <summary>
    /// Received shares follow the owner's account default expiry. "indefinite" is honoured only because the owner
    /// chose it explicitly; an unknown or missing mode falls back to <paramref name="defaultExpiryDays"/> (minimum 1).
    /// </summary>
    public static ReceivedShareExpiry ResolveExpiry(string? ownerDefaultExpiryMode, int defaultExpiryDays, DateTime nowUtc)
    {
        var mode = (ownerDefaultExpiryMode ?? string.Empty).Trim().ToLowerInvariant();
        DateTime? expiresAtUtc = mode switch
        {
            "1_hour" => nowUtc.AddHours(1),
            "24_hours" => nowUtc.AddHours(24),
            "7_days" => nowUtc.AddDays(7),
            "30_days" => nowUtc.AddDays(30),
            "1_year" => nowUtc.AddYears(1),
            _ => null
        };

        if (mode == "indefinite")
        {
            return new ReceivedShareExpiry("indefinite", null);
        }

        if (expiresAtUtc is null)
        {
            expiresAtUtc = nowUtc.AddDays(Math.Max(1, defaultExpiryDays));
            mode = "date";
        }

        return new ReceivedShareExpiry(mode, expiresAtUtc);
    }

    /// <summary>
    /// Returns the client-safe reason the owner's daily quota rejects another received share, or null when it fits.
    /// </summary>
    public static string? CheckDailyQuota(int sharesLast24h, long bytesLast24h, long incomingBytes, AgoraPublicUploadOptions options)
    {
        if (options.MaxSharesPerCodePerDay > 0 && sharesLast24h >= options.MaxSharesPerCodePerDay)
        {
            return "This upload link has received its daily limit of uploads. Please try again tomorrow.";
        }

        if (options.MaxBytesPerCodePerDay > 0 && bytesLast24h + incomingBytes > options.MaxBytesPerCodePerDay)
        {
            return "This upload link has received its daily data limit. Please try again tomorrow.";
        }

        return null;
    }
}
