using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Agora.Application.Tests;

/// <summary>
/// Background jobs have no request, so their emailed share links come from <see cref="IPublicOriginProvider"/>
/// (the configured origin); the site-relative fallback exists only for Development without the setting.
/// </summary>
public sealed class PublicOriginTests
{
    [Fact]
    public void ShareUrl_UsesTheConfiguredOriginOrFallsBackToARelativePath()
    {
        Assert.Equal("https://files.example.com/s/abc123", new PublicBaseUrlResolver("https://files.example.com", false).ShareUrl("abc123"));
        Assert.Equal("/s/abc123", new PublicBaseUrlResolver(null, true).ShareUrl("abc123"));
    }

    [Theory]
    [InlineData("https://files.example.com", "https://files.example.com/s/tok-1")]
    [InlineData(null, "/s/tok-1")]
    public async Task EmailNotificationJob_BuildsTheShareLinkFromThePublicOrigin(string? origin, string expectedUrl)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options;
        await using var db = new AgoraDbContext(options);
        await db.Database.EnsureCreatedAsync();

        var share = new Share
        {
            Id = Guid.NewGuid(),
            UploaderEmail = "owner@example.com",
            ShareToken = "tok-1",
            ZipDisplayName = "files.zip",
            ZipDiskPath = "zips/tok-1.zip",
            CreatedAtUtc = DateTime.UtcNow
        };
        var downloadEvent = new DownloadEvent
        {
            Id = Guid.NewGuid(),
            ShareId = share.Id,
            Share = share,
            IpAddress = "203.0.113.9",
            DownloadedAtUtc = DateTime.UtcNow
        };
        db.Shares.Add(share);
        db.DownloadEvents.Add(downloadEvent);
        await db.SaveChangesAsync();

        var sender = new CapturingEmailSender();
        var job = new EmailNotificationJob(
            db,
            sender,
            new BareIpGeoLookup(),
            new PublicBaseUrlResolver(origin, allowRequestHostFallback: origin is null),
            NullLogger<EmailNotificationJob>.Instance);

        await job.ProcessDownloadEventAsync(downloadEvent.Id, share.ShareToken, CancellationToken.None);

        var notification = Assert.Single(sender.Sent);
        Assert.Equal(expectedUrl, notification.ShareUrl);
        Assert.Equal("owner@example.com", notification.To);
        Assert.True((await db.DownloadEvents.SingleAsync(x => x.Id == downloadEvent.Id)).NotificationSent);
    }

    private sealed class CapturingEmailSender : IEmailSender
    {
        public List<DownloadNotification> Sent { get; } = [];

        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
        {
            Sent.Add(notification);
            return Task.CompletedTask;
        }

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class BareIpGeoLookup : IDownloaderGeoLookup
    {
        public Task<string> FormatForNotificationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult(ipAddress);
    }
}
