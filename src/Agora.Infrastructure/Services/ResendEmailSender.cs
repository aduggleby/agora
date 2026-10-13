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
    IEmailTemplateRenderer templateRenderer,
    ILogger<ResendEmailSender> logger) : IEmailSender
{
    private readonly EmailSenderOptions _options = options.Value;

    public async Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
    {
        var html = await templateRenderer.RenderDownloadNotificationHtmlAsync(notification, cancellationToken);
        await SendHtmlEmailAsync(notification.To, "Your shared file was downloaded", html, cancellationToken);
    }

    public async Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        var html = await templateRenderer.RenderAuthEmailHtmlAsync(message, cancellationToken);
        await SendHtmlEmailAsync(message.To, message.Subject, html, cancellationToken, message.FromDisplayNameOverride);
    }

    private async Task SendHtmlEmailAsync(
        string to,
        string subject,
        string html,
        CancellationToken cancellationToken,
        string? fromDisplayNameOverride = null)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiToken))
        {
            logger.LogWarning("Email API token not configured; skipping email with subject {Subject}.", subject);
            return;
        }

        httpClient.BaseAddress = new Uri(_options.ApiUrl);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiToken);

        var body = new
        {
            from = BuildFromValue(fromDisplayNameOverride),
            to = new[] { to },
            subject,
            html
        };

        using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        var response = await httpClient.PostAsync("/emails", content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new InvalidOperationException($"Resend request failed ({(int)response.StatusCode}): {responseBody}");
        }
    }

    private string BuildFromValue(string? fromDisplayNameOverride)
    {
        var address = (_options.FromAddress ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(address))
        {
            return "no-reply@example.com";
        }

        var displayName = (fromDisplayNameOverride ?? _options.FromDisplayName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return address;
        }

        var escapedDisplay = displayName.Replace("\"", "'");
        return $"\"{escapedDisplay}\" <{address}>";
    }
}
