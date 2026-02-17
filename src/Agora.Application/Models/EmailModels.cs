namespace Agora.Application.Models;

public sealed record DownloadNotification(
    string To,
    string ShareId,
    string ShareUrl,
    string ZipDisplayName,
    DateTime DownloadedAtUtc,
    string DownloaderIp,
    string DownloaderUserAgent,
    string BrowserMetadataJson);

public sealed class EmailSenderOptions
{
    public const string Section = "Email:Resend";
    public string ApiToken { get; set; } = string.Empty;
    public string ApiUrl { get; set; } = "https://api.resend.com";
    public string FromAddress { get; set; } = "no-reply@example.com";
}
