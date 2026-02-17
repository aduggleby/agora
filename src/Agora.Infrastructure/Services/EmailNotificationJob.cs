using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Agora.Infrastructure.Services;

public sealed class EmailNotificationJob(
    AgoraDbContext db,
    IEmailSender emailSender,
    IOptions<AgoraOptions> options,
    ILogger<EmailNotificationJob> logger)
{
    private readonly AgoraOptions _options = options.Value;

    public async Task ProcessDownloadEventAsync(Guid downloadEventId, string token, CancellationToken cancellationToken)
    {
        var downloadEvent = await db.DownloadEvents
            .Include(x => x.Share)
            .SingleOrDefaultAsync(x => x.Id == downloadEventId, cancellationToken);

        if (downloadEvent is null)
        {
            return;
        }

        if (downloadEvent.NotificationSent)
        {
            return;
        }

        var share = downloadEvent.Share;
        if (share is null)
        {
            return;
        }

        try
        {
            var downloadCount = await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id, cancellationToken);
            var browser = ParseBrowserMetadata(downloadEvent.BrowserMetadataJson);
            var shareUrl = BuildShareUrl(token);

            var notification = new DownloadNotification(
                To: share.UploaderEmail,
                ShareId: share.Id.ToString(),
                ShareUrl: shareUrl,
                ZipDisplayName: share.ZipDisplayName,
                DownloadedAtUtc: downloadEvent.DownloadedAtUtc,
                DownloaderIp: downloadEvent.IpAddress,
                DownloaderUserAgent: downloadEvent.UserAgent,
                BrowserMetadataJson: downloadEvent.BrowserMetadataJson,
                ExpiresAtUtc: share.ExpiresAtUtc,
                DownloadCount: downloadCount,
                BrowserFamily: browser.BrowserFamily,
                OsFamily: browser.OsFamily,
                DeviceType: browser.DeviceType);

            await emailSender.SendDownloadNotificationAsync(notification, cancellationToken);
            downloadEvent.NotificationSent = true;
            downloadEvent.NotificationError = null;
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Download notification failed for event {EventId}", downloadEventId);
            downloadEvent.NotificationError = ex.Message;
            await db.SaveChangesAsync(cancellationToken);
        }
    }

    private string BuildShareUrl(string token)
    {
        var configuredBase = (_options.PublicBaseUrl ?? string.Empty).Trim().TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(configuredBase))
        {
            return $"{configuredBase}/s/{token}";
        }

        return $"/s/{token}";
    }

    private static (string BrowserFamily, string OsFamily, string DeviceType) ParseBrowserMetadata(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
            var root = doc.RootElement;
            var browser = root.TryGetProperty("browserFamily", out var b) ? b.GetString() ?? "Unknown" : "Unknown";
            var os = root.TryGetProperty("osFamily", out var o) ? o.GetString() ?? "Unknown" : "Unknown";
            var device = root.TryGetProperty("deviceType", out var d) ? d.GetString() ?? "Unknown" : "Unknown";
            return (browser, os, device);
        }
        catch
        {
            return ("Unknown", "Unknown", "Unknown");
        }
    }
}
