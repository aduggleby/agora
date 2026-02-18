using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

public sealed class FileSystemEmailSender(
    IOptions<FileSystemEmailOptions> options,
    IEmailTemplateRenderer templateRenderer,
    ILogger<FileSystemEmailSender> logger) : IEmailSender
{
    private readonly FileSystemEmailOptions _options = options.Value;

    public async Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
    {
        var html = await templateRenderer.RenderDownloadNotificationHtmlAsync(notification, cancellationToken);
        await WriteEmailAsync(
            to: notification.To,
            subject: "Your shared file was downloaded",
            kind: "download_notification",
            metadata: new
            {
                notification.ShareId,
                notification.ShareUrl,
                notification.ZipDisplayName,
                notification.DownloadedAtUtc,
                notification.DownloaderIp,
                notification.DownloaderIpDisplay,
                notification.DownloaderUserAgent,
                notification.BrowserMetadataJson
            },
            html: html,
            cancellationToken: cancellationToken);
    }

    public async Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        var html = await templateRenderer.RenderAuthEmailHtmlAsync(message, cancellationToken);
        await WriteEmailAsync(
            to: message.To,
            subject: message.Subject,
            kind: "auth",
            metadata: new
            {
                message.Preheader,
                message.Headline,
                message.ActionLabel,
                message.ActionUrl
            },
            html: html,
            cancellationToken: cancellationToken);
    }

    private async Task WriteEmailAsync(string to, string subject, string kind, object metadata, string html, CancellationToken cancellationToken)
    {
        var outputDirectory = string.IsNullOrWhiteSpace(_options.OutputDirectory) ? "emails" : _options.OutputDirectory;
        Directory.CreateDirectory(outputDirectory);

        var fileName = $"{DateTime.UtcNow:yyyyMMdd-HHmmssfff}-{Guid.NewGuid():N}.json";
        var fullPath = Path.Combine(outputDirectory, fileName);

        var payload = new
        {
            provider = "filesystem",
            to,
            subject,
            kind,
            metadata,
            html
        };

        await File.WriteAllTextAsync(fullPath, JsonSerializer.Serialize(payload, new JsonSerializerOptions
        {
            WriteIndented = true
        }), cancellationToken);

        logger.LogInformation("Wrote development email ({Subject}) to {Path}", subject, fullPath);
    }
}
