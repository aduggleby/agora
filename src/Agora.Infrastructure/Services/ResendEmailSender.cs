using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

public sealed class ResendEmailSender(
    HttpClient httpClient,
    IOptions<EmailSenderOptions> options,
    ILogger<ResendEmailSender> logger) : IEmailSender
{
    private readonly EmailSenderOptions _options = options.Value;

    public async Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiToken))
        {
            logger.LogWarning("Email API token not configured; skipping download notification.");
            return;
        }

        httpClient.BaseAddress = new Uri(_options.ApiUrl);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken);

        var body = new
        {
            from = _options.FromAddress,
            to = new[] { notification.To },
            subject = "Your shared file was downloaded",
            html = $"<p>Your shared file <strong>{notification.ZipDisplayName}</strong> was downloaded.</p>" +
                   $"<p>Time (UTC): {notification.DownloadedAtUtc:O}<br/>IP: {notification.DownloaderIp}<br/>User Agent: {notification.DownloaderUserAgent}</p>" +
                   $"<p>Share: <a href=\"{notification.ShareUrl}\">{notification.ShareUrl}</a></p>"
        };

        using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        var response = await httpClient.PostAsync("/emails", content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException($"Resend request failed ({(int)response.StatusCode}): {responseBody}");
        }
    }
}
