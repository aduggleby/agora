using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

public sealed class FileSystemEmailSender(
    IOptions<FileSystemEmailOptions> options,
    ILogger<FileSystemEmailSender> logger) : IEmailSender
{
    private readonly FileSystemEmailOptions _options = options.Value;

    public async Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
    {
        var outputDirectory = string.IsNullOrWhiteSpace(_options.OutputDirectory) ? "emails" : _options.OutputDirectory;
        Directory.CreateDirectory(outputDirectory);

        var fileName = $"{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{notification.ShareId}.json";
        var fullPath = Path.Combine(outputDirectory, fileName);

        var payload = new
        {
            provider = "filesystem",
            notification.To,
            notification.ShareId,
            notification.ShareUrl,
            notification.ZipDisplayName,
            notification.DownloadedAtUtc,
            notification.DownloaderIp,
            notification.DownloaderUserAgent,
            notification.BrowserMetadataJson
        };

        await File.WriteAllTextAsync(fullPath, JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true
        }), cancellationToken);

        logger.LogInformation("Wrote development email notification to {Path}", fullPath);
    }
}
