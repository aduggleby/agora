namespace Agora.Application.Models;

public sealed record DownloadNotification(
    string To,
    string ShareId,
    string ShareUrl,
    string ZipDisplayName,
    DateTime DownloadedAtUtc,
    string DownloaderIp,
    string DownloaderUserAgent,
    string BrowserMetadataJson,
    DateTime? ExpiresAtUtc,
    int DownloadCount,
    string BrowserFamily,
    string OsFamily,
    string DeviceType,
    string DownloaderIpDisplay,
    int BatchCount = 1,
    DateTime? BatchFirstDownloadedAtUtc = null);

public static class DownloadNotificationText
{
    /// <summary>Subject line of a download notification; a coalesced one names how many downloads it covers.</summary>
    public static string Subject(DownloadNotification notification) => notification.BatchCount > 1
        ? $"Your shared file was downloaded {notification.BatchCount} times"
        : "Your shared file was downloaded";
}

public sealed record AuthEmailMessage(
    string To,
    string Subject,
    string Preheader,
    string Headline,
    string IntroText,
    string? DetailText,
    string? ActionLabel,
    string? ActionUrl,
    string? SecondaryText,
    string? FromDisplayNameOverride = null);

public sealed class EmailSenderOptions
{
    public const string Section = "Email:Resend";
    public string ApiToken { get; set; } = string.Empty;
    public string ApiUrl { get; set; } = "https://api.resend.com";
    public string FromDisplayName { get; set; } = string.Empty;
    public string FromAddress { get; set; } = "no-reply@example.com";
}

public sealed class FileSystemEmailOptions
{
    public const string Section = "Email:FileSystem";
    public string OutputDirectory { get; set; } = "emails";
}
