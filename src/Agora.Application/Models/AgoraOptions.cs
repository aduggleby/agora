namespace Agora.Application.Models;

public sealed class AgoraOptions
{
    public const string Section = "Agora";
    /// <summary>Public origin of the site (https://host[:port]); required outside Development and E2E.</summary>
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// Reverse proxies (IP addresses and CIDR networks) whose X-Forwarded-For/Proto/Host headers are honoured.
    /// Loopback is always trusted; everything else is ignored unless listed here.
    /// </summary>
    public string? TrustedProxies { get; set; }
    public string StorageRoot { get; set; } = "storage";
    public int MaxFilesPerShare { get; set; } = 20;
    public long MaxFileSizeBytes { get; set; } = 5L * 1024 * 1024 * 1024;
    public long MaxTotalUploadBytes { get; set; } = 10L * 1024 * 1024 * 1024;
    public int DownloadEventRetentionDays { get; set; } = 90;
    public int ZombieUploadRetentionHours { get; set; } = 24;
    public AgoraPreviewOptions Previews { get; set; } = new();
    public AgoraAuthOptions Auth { get; set; } = new();
    public AgoraGeoLookupOptions GeoLookup { get; set; } = new();
    public AgoraRateLimitOptions RateLimits { get; set; } = new();
}

/// <summary>
/// Whether download notifications look up the downloader's city and country. The lookup sends the downloader's
/// public IP address to the third-party service ipwho.is; disable it to keep that data in-house.
/// </summary>
public sealed class AgoraGeoLookupOptions
{
    public bool Enabled { get; set; } = true;
}

/// <summary>Per-client request budgets enforced by the rate limiter.</summary>
public sealed class AgoraRateLimitOptions
{
    /// <summary>Requests per minute an anonymous client (keyed by IP address) may make across the whole site; 0 disables the budget.</summary>
    public int AnonymousPerMinute { get; set; } = 1200;
}

/// <summary>
/// Sign-in cookie lifetime and how often a signed-in session is checked against the user record
/// (enabled flag, role, security stamp).
/// </summary>
public sealed class AgoraAuthOptions
{
    /// <summary>Sliding lifetime of the sign-in cookie, in days.</summary>
    public int SessionLifetimeDays { get; set; } = 14;

    /// <summary>
    /// Longest time a session keeps working after the user is disabled, demoted, deleted or changes credentials:
    /// the cookie is revalidated against the database at most this often.
    /// </summary>
    public int SessionRevalidationMinutes { get; set; } = 5;

    /// <summary>
    /// When the sign-in and CSRF cookies get the Secure flag. Auto: always in Production, only on HTTPS requests
    /// elsewhere. SameAsRequest on a public HTTP site lets anyone on the path read the session cookie.
    /// </summary>
    public SecureCookiesMode SecureCookies { get; set; } = SecureCookiesMode.Auto;
}

public enum SecureCookiesMode
{
    Auto,
    Always,
    SameAsRequest
}

/// <summary>
/// Budgets for preview and thumbnail generation of uploaded files. Sources above a budget are not decoded at all;
/// the share shows the "preview unavailable" image instead.
/// </summary>
public sealed class AgoraPreviewOptions
{
    /// <summary>Largest image or PDF (in bytes) that is opened for a preview.</summary>
    public long MaxSourceBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>Largest image (width times height) that is decoded for a preview; checked from the header before decoding.</summary>
    public long MaxSourcePixels { get; set; } = 50_000_000;

    /// <summary>Wall-clock budget for generating one preview or thumbnail.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}
