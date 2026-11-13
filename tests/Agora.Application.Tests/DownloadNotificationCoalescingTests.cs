using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>
/// <c>every_time</c> notifications: at most one email per share per window, each covering every download since
/// the previous one.
/// </summary>
public sealed class DownloadNotificationCoalescingTests
{
    [Fact]
    public async Task One_download_sends_one_email_right_away()
    {
        await using var harness = await Harness.CreateAsync();

        await harness.RecordDownloadAsync();

        var job = Assert.Single(harness.Jobs.Created);
        Assert.IsType<EnqueuedState>(job.State);
        await harness.RunJobsAsync();
        var email = Assert.Single(harness.Emails.Sent);
        Assert.Equal(1, email.BatchCount);
        Assert.Equal("Your shared file was downloaded", DownloadNotificationText.Subject(email));
        Assert.True(await harness.AllEventsNotifiedAsync());
    }

    [Fact]
    public async Task Downloads_within_the_window_are_summarized_in_one_email()
    {
        await using var harness = await Harness.CreateAsync();

        for (var i = 0; i < 5; i++)
        {
            await harness.RecordDownloadAsync();
        }

        Assert.Single(harness.Jobs.Created);
        await harness.RunJobsAsync();
        var email = Assert.Single(harness.Emails.Sent);
        Assert.Equal(5, email.BatchCount);
        Assert.NotNull(email.BatchFirstDownloadedAtUtc);
        Assert.True(email.BatchFirstDownloadedAtUtc <= email.DownloadedAtUtc);
        Assert.Equal("Your shared file was downloaded 5 times", DownloadNotificationText.Subject(email));
        Assert.True(await harness.AllEventsNotifiedAsync());

        // Another download right after an email waits for the window instead of sending at once.
        await harness.RecordDownloadAsync();
        var delayed = Assert.IsType<ScheduledState>(harness.Jobs.Created.Last().State);
        Assert.True(delayed.EnqueueAt > DateTime.UtcNow.AddMinutes(4));
        await harness.RecordDownloadAsync();
        Assert.Single(harness.Jobs.Created);
        await harness.RunJobsAsync();
        Assert.Equal(2, harness.Emails.Sent.Count);
        Assert.Equal(2, harness.Emails.Sent[1].BatchCount);
    }

    [Fact]
    public async Task A_download_after_the_window_starts_a_new_email()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.RecordDownloadAsync();
        await harness.RunJobsAsync();
        Assert.Single(harness.Emails.Sent);

        await harness.BackdateEventsAsync(TimeSpan.FromMinutes(11));
        await harness.RecordDownloadAsync();

        Assert.IsType<EnqueuedState>(harness.Jobs.Created.Last().State);
        await harness.RunJobsAsync();
        Assert.Equal(2, harness.Emails.Sent.Count);
        Assert.Equal(1, harness.Emails.Sent[1].BatchCount);
    }

    [Fact]
    public async Task A_lost_job_does_not_block_later_notifications()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.RecordDownloadAsync();
        harness.Jobs.Created.Clear(); // The job never runs.

        await harness.BackdateEventsAsync(TimeSpan.FromMinutes(11));
        await harness.RecordDownloadAsync();

        Assert.Single(harness.Jobs.Created);
        await harness.RunJobsAsync();
        var email = Assert.Single(harness.Emails.Sent);
        Assert.Equal(2, email.BatchCount);
    }

    [Fact]
    public async Task A_failed_send_is_recorded_and_a_later_download_notifies_again()
    {
        await using var harness = await Harness.CreateAsync();
        harness.Emails.Fail = true;
        await harness.RecordDownloadAsync();
        await harness.RunJobsAsync();

        Assert.Empty(harness.Emails.Sent);
        var failed = Assert.Single(await harness.EventsAsync());
        Assert.False(failed.NotificationSent);
        Assert.Equal("mail provider down", failed.NotificationError);

        // The errored event no longer counts as pending; the recent attempt keeps the window, so the next one waits.
        harness.Emails.Fail = false;
        await harness.RecordDownloadAsync();
        Assert.IsType<ScheduledState>(Assert.Single(harness.Jobs.Created).State);
        await harness.RunJobsAsync();
        Assert.Equal(1, Assert.Single(harness.Emails.Sent).BatchCount);
    }

    [Fact]
    public async Task A_download_during_the_send_gets_the_next_email()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.RecordDownloadAsync();
        harness.Emails.DuringSend = harness.RecordDownloadAsync;

        await harness.RunJobsAsync();

        // The second download saw a pending one and queued nothing; the job rescheduled itself for it.
        var sent = Assert.Single(harness.Emails.Sent);
        Assert.Equal(1, sent.BatchCount);
        var rescheduled = Assert.Single(harness.Jobs.Created);
        Assert.IsType<ScheduledState>(rescheduled.State);
        await harness.RunJobsAsync();
        Assert.Equal(2, harness.Emails.Sent.Count);
        Assert.Equal(1, harness.Emails.Sent[1].BatchCount);
        Assert.True(await harness.AllEventsNotifiedAsync());
    }

    [Fact]
    public async Task Once_notifies_the_first_download_only_and_none_never_notifies()
    {
        await using (var once = await Harness.CreateAsync("once"))
        {
            await once.RecordDownloadAsync();
            await once.RecordDownloadAsync();
            var job = Assert.Single(once.Jobs.Created);
            Assert.Equal(nameof(EmailNotificationJob.ProcessDownloadEventAsync), job.Job.Method.Name);
            Assert.IsType<EnqueuedState>(job.State);
        }

        await using var none = await Harness.CreateAsync("none");
        await none.RecordDownloadAsync();
        await none.RecordDownloadAsync();
        Assert.Empty(none.Jobs.Created);
        Assert.Equal(2, (await none.EventsAsync()).Count);
    }

    [Fact]
    public async Task A_disabled_owner_gets_no_download_email()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.RecordDownloadAsync();
        await harness.SetOwnerEnabledAsync(false);

        await harness.RunJobsAsync();

        Assert.Empty(harness.Emails.Sent);
        var skipped = Assert.Single(await harness.EventsAsync());
        Assert.False(skipped.NotificationSent);
        Assert.Equal("Share deleted, or owner not found or disabled.", skipped.NotificationError);
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _storageRoot;
        private readonly Guid _shareId;

        private Harness(SqliteConnection connection, string storageRoot, Guid shareId)
        {
            _connection = connection;
            _storageRoot = storageRoot;
            _shareId = shareId;
        }

        public RecordingJobClient Jobs { get; } = new();
        public CapturingEmailSender Emails { get; } = new();

        public static async Task<Harness> CreateAsync(string notifyMode = "every_time")
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-notify-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var owner = new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = "owner@example.com",
                EmailConfirmed = true,
                PasswordHash = "x:y",
                SecurityStamp = SecurityStamps.New(),
                UploadToken = "owner001",
                CreatedAtUtc = DateTime.UtcNow
            };
            var share = new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = owner.Id,
                UploaderEmail = owner.Email,
                ShareToken = "notify01",
                ZipDisplayName = "files.zip",
                ZipDiskPath = "zips/notify01.zip",
                NotifyMode = notifyMode,
                CreatedAtUtc = DateTime.UtcNow
            };
            await using (var db = NewDb(connection))
            {
                await db.Database.EnsureCreatedAsync();
                db.Users.Add(owner);
                db.Shares.Add(share);
                await db.SaveChangesAsync();
            }

            return new Harness(connection, storageRoot, share.Id);
        }

        public async Task RecordDownloadAsync()
        {
            await using var db = NewDb(_connection);
            var options = Options.Create(new AgoraOptions { StorageRoot = _storageRoot });
            var objectStore = new FileSystemObjectStore(_storageRoot);
            var scratch = new ScratchSpaceMonitor(options.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
            var manager = new ShareManager(db, options, new ShareContentStore(objectStore), objectStore, Jobs, new KeyedAsyncLock(), scratch, NullLogger<ShareManager>.Instance);
            var share = await db.Shares.SingleAsync(x => x.Id == _shareId);
            await manager.RecordDownloadAsync(share, share.ShareToken, "203.0.113.9", "test-agent", CancellationToken.None);
        }

        /// <summary>Runs every recorded coalesced-notification job once, in order, then forgets them.</summary>
        public async Task RunJobsAsync()
        {
            var jobs = Jobs.Created.ToList();
            Jobs.Created.Clear();
            foreach (var (job, _) in jobs)
            {
                Assert.Equal(nameof(EmailNotificationJob.ProcessShareDownloadsAsync), job.Method.Name);
                await using var db = NewDb(_connection);
                var notificationJob = new EmailNotificationJob(
                    db,
                    Emails,
                    new BareIpGeoLookup(),
                    new PublicBaseUrlResolver("https://files.example.com", allowRequestHostFallback: false),
                    Jobs,
                    NullLogger<EmailNotificationJob>.Instance);
                await notificationJob.ProcessShareDownloadsAsync((Guid)job.Args[0], (string)job.Args[1], CancellationToken.None);
            }
        }

        public async Task SetOwnerEnabledAsync(bool enabled)
        {
            await using var db = NewDb(_connection);
            var share = await db.Shares.SingleAsync(x => x.Id == _shareId);
            var owner = await db.Users.SingleAsync(x => x.Id == share.OwnerUserId);
            owner.IsEnabled = enabled;
            await db.SaveChangesAsync();
        }

        public async Task<List<DownloadEvent>> EventsAsync()
        {
            await using var db = NewDb(_connection);
            return await db.DownloadEvents.AsNoTracking().Where(x => x.ShareId == _shareId).OrderBy(x => x.DownloadedAtUtc).ToListAsync();
        }

        public async Task<bool> AllEventsNotifiedAsync()
        {
            await using var db = NewDb(_connection);
            return await db.DownloadEvents.AllAsync(x => x.ShareId == _shareId && x.NotificationSent);
        }

        public async Task BackdateEventsAsync(TimeSpan by)
        {
            await using var db = NewDb(_connection);
            foreach (var downloadEvent in await db.DownloadEvents.Where(x => x.ShareId == _shareId).ToListAsync())
            {
                downloadEvent.DownloadedAtUtc = downloadEvent.DownloadedAtUtc - by;
            }

            await db.SaveChangesAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }

        private static AgoraDbContext NewDb(SqliteConnection connection) =>
            new(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
    }

    private sealed class RecordingJobClient : IBackgroundJobClient
    {
        public List<(Job Job, IState State)> Created { get; } = [];

        public string Create(Job job, IState state)
        {
            Created.Add((job, state));
            return Guid.NewGuid().ToString("N");
        }

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }

    private sealed class CapturingEmailSender : IEmailSender
    {
        public List<DownloadNotification> Sent { get; } = [];
        public bool Fail { get; set; }
        /// <summary>Runs inside the send, before it completes (a download arriving while the email goes out).</summary>
        public Func<Task>? DuringSend { get; set; }

        public async Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken)
        {
            if (DuringSend is { } during)
            {
                DuringSend = null;
                await during();
            }

            if (Fail)
            {
                throw new InvalidOperationException("mail provider down");
            }

            Sent.Add(notification);
        }

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class BareIpGeoLookup : IDownloaderGeoLookup
    {
        public Task<string> FormatForNotificationAsync(string ipAddress, CancellationToken cancellationToken) => Task.FromResult(ipAddress);
    }
}
