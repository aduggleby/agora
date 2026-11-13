using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Hangfire;
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
    IBackgroundJobClient backgroundJobs,
    ILogger<EmailNotificationJob> logger)
{
    /// <summary><c>every_time</c> shares get at most one download email per share in this window.</summary>
    public static readonly TimeSpan CoalesceWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The coalesced <c>every_time</c> notification: one email for all downloads of the share not yet notified
    /// (the latest one in detail, plus how many since the first). Downloads recorded while it ran get the next email,
    /// one window later.
    /// </summary>
    // One run per share at a time (a rescheduled job and a fresh one can meet); the job is idempotent, so a lock
    // timeout or database error may simply retry. Send failures are caught and recorded on the events instead.
    [DisableConcurrentExecution("agora:share-download-notification:{0}", 60)]
    [AutomaticRetry(Attempts = 3)]
    public async Task ProcessShareDownloadsAsync(Guid shareId, string token, CancellationToken cancellationToken, PerformContext? performContext = null)
    {
        performContext?.WriteLine($"Processing coalesced download notification for share '{shareId}'.");
        var pending = await db.DownloadEvents
            .Where(x => x.ShareId == shareId && !x.NotificationSent && x.NotificationError == null)
            .OrderBy(x => x.DownloadedAtUtc)
            .ToListAsync(cancellationToken);
        if (pending.Count == 0)
        {
            performContext?.WriteLine("Notification skipped: no downloads waiting.");
            return;
        }

        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(x => x.Id == shareId, cancellationToken);
        var ownerUserId = share?.OwnerUserId;
        var recipient = share is null || ownerUserId is null || share.DeletedAtUtc is not null
            ? null
            : await db.Users.Where(x => x.Id == ownerUserId && x.IsEnabled).Select(x => x.Email).SingleOrDefaultAsync(cancellationToken);
        if (share is null || string.IsNullOrWhiteSpace(recipient))
        {
            performContext?.WriteLine("Notification skipped: share deleted, or owner not found or disabled.");
            pending.ForEach(x => x.NotificationError = "Share deleted, or owner not found or disabled.");
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        try
        {
            var latest = pending[^1];
            var notification = await BuildNotificationAsync(share, latest, recipient, token, cancellationToken) with
            {
                BatchCount = pending.Count,
                BatchFirstDownloadedAtUtc = pending[0].DownloadedAtUtc
            };
            await emailSender.SendDownloadNotificationAsync(notification, cancellationToken);
            pending.ForEach(x =>
            {
                x.NotificationSent = true;
                x.NotificationError = null;
            });
            await db.SaveChangesAsync(cancellationToken);
            performContext?.WriteLine($"Download notification for {pending.Count} download(s) sent to '{recipient}'.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Coalesced download notification failed for share {ShareId}", shareId);
            performContext?.WriteLine($"Download notification failed: {ex.Message}");
            pending.ForEach(x => x.NotificationError = ex.Message);
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        // A download recorded between the query above and the save saw a pending event and queued nothing.
        var pendingIds = pending.Select(x => x.Id).ToList();
        var arrivedMeanwhile = await db.DownloadEvents.AnyAsync(
            x => x.ShareId == shareId && !x.NotificationSent && x.NotificationError == null && !pendingIds.Contains(x.Id),
            cancellationToken);
        if (arrivedMeanwhile)
        {
            backgroundJobs.Schedule<EmailNotificationJob>(x => x.ProcessShareDownloadsAsync(shareId, token, CancellationToken.None, null), CoalesceWindow);
        }
    }

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
            : await db.Users.Where(x => x.Id == ownerUserId && x.IsEnabled).Select(x => x.Email).SingleOrDefaultAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(recipient))
        {
            performContext?.WriteLine("Notification skipped: share deleted, or owner not found or disabled.");
            downloadEvent.NotificationError = "Share deleted, or owner not found or disabled.";
            await db.SaveChangesAsync(cancellationToken);
            return;
        }

        try
        {
            var notification = await BuildNotificationAsync(share, downloadEvent, recipient, token, cancellationToken);
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

    private async Task<DownloadNotification> BuildNotificationAsync(Share share, DownloadEvent downloadEvent, string recipient, string token, CancellationToken cancellationToken)
    {
        var downloadCount = await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id, cancellationToken);
        var browser = ParseBrowserMetadata(downloadEvent.BrowserMetadataJson);
        var downloaderIpDisplay = await downloaderGeoLookup.FormatForNotificationAsync(downloadEvent.IpAddress, cancellationToken);

        return new DownloadNotification(
            To: recipient,
            ShareId: share.Id.ToString(),
            ShareUrl: publicOrigin.ShareUrl(token),
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
