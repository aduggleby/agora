using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Agora.Infrastructure.Services;

public sealed class EmailNotificationJob(
    AgoraDbContext db,
    IEmailSender emailSender,
    ILogger<EmailNotificationJob> logger)
{
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
            var notification = new DownloadNotification(
                To: share.UploaderEmail,
                ShareId: share.Id.ToString(),
                ShareUrl: $"/s/{token}",
                ZipDisplayName: share.ZipDisplayName,
                DownloadedAtUtc: downloadEvent.DownloadedAtUtc,
                DownloaderIp: downloadEvent.IpAddress,
                DownloaderUserAgent: downloadEvent.UserAgent,
                BrowserMetadataJson: downloadEvent.BrowserMetadataJson);

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
}
