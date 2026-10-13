using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Hangfire.Console;
using Hangfire.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace Agora.Infrastructure.Services;

public sealed class EmailNotificationJob(
    AgoraDbContext db,
    IEmailSender emailSender,
    IDownloaderGeoLookup downloaderGeoLookup,
    IPublicOriginProvider publicOrigin,
    ILogger<EmailNotificationJob> logger)
{
    public async Task ProcessDownloadEventAsync(Guid downloadEventId, string token, CancellationToken cancellationToken, PerformContext? performContext = null)
    {
        performContext?.WriteLine($"Processing download notification for event '{downloadEventId}'.");
        var downloadEvent = await db.DownloadEvents
            .Include(x => x.Share)
            .SingleOrDefaultAsync(x => x.Id == downloadEventId, cancellationToken);

        if (downloadEvent is null)
        {
            performContext?.WriteLine("Notification skipped: download event not found.");
            return;
        }

        if (downloadEvent.NotificationSent)
        {
            performContext?.WriteLine("Notification skipped: already sent.");
            return;
        }

        var share = downloadEvent.Share;
        if (share is null)
        {
            performContext?.WriteLine("Notification skipped: share not found.");
            return;
        }

        // The recipient is the account that owns the share, looked up at send time; the address stored on the share
        // is display data and may be stale.
        var ownerUserId = share.OwnerUserId;
        var recipient = ownerUserId is null || share.DeletedAtUtc is not null
            ? null
            : await db.Users.Where(x => x.Id == ownerUserId).Select(x => x.Email).SingleOrDefaultAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(recipient))
        {
            performContext?.WriteLine("Notification skipped: share deleted or owner not found.");
            downloadEvent.NotificationError = "Share deleted or owner not found.";
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        try
        {
            var downloadCount = await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id, cancellationToken);
            var browser = ParseBrowserMetadata(downloadEvent.BrowserMetadataJson);
            var shareUrl = publicOrigin.ShareUrl(token);
            var downloaderIpDisplay = await downloaderGeoLookup.FormatForNotificationAsync(downloadEvent.IpAddress, cancellationToken);

            var notification = new DownloadNotification(
                To: recipient,
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
                DeviceType: browser.DeviceType,
                DownloaderIpDisplay: downloaderIpDisplay);

            await emailSender.SendDownloadNotificationAsync(notification, cancellationToken);
            downloadEvent.NotificationSent = true;
            downloadEvent.NotificationError = null;
            await db.SaveChangesAsync(cancellationToken);
            performContext?.WriteLine($"Download notification sent to '{recipient}'.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Download notification failed for event {EventId}", downloadEventId);
            performContext?.WriteLine($"Download notification failed: {ex.Message}");
            downloadEvent.NotificationError = ex.Message;
            await db.SaveChangesAsync(cancellationToken);
        }
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
