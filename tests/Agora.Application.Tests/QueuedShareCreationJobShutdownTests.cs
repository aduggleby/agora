using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Hubs;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>
/// A server shutdown (Hangfire's stop token) interrupts a queued creation without failing it: the job is rethrown so
/// Hangfire requeues it, and the status is not marked failed. Any other error still marks the creation failed.
/// </summary>
public sealed class QueuedShareCreationJobShutdownTests
{
    private const string ShareToken = "Ab12cd34";

    [Fact]
    public async Task Shutdown_cancellation_is_rethrown_and_does_not_mark_the_creation_failed()
    {
        using var cts = new CancellationTokenSource();
        await using var fixture = await Fixture.CreateAsync(onBroadcast: n =>
        {
            if (n == 2)
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Job.ProcessAsync(Fixture.Payload(), cts.Token));

        var entry = fixture.Status.Read(ShareToken);
        Assert.NotNull(entry);
        Assert.NotEqual("failed", entry.State);
    }

    [Fact]
    public async Task Shutdown_after_the_share_was_created_completes_instead_of_requeueing()
    {
        using var cts = new CancellationTokenSource();
        await using var fixture = await Fixture.CreateAsync(onBroadcast: n =>
        {
            // Broadcast 5 reports "create_share" completed, right after the share row is committed.
            if (n == 5)
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
        });
        fixture.Db.Users.Add(new UserAccount
        {
            Id = fixture.OwnerId,
            Email = "owner@example.com",
            EmailConfirmed = true,
            PasswordHash = "x:y",
            SecurityStamp = SecurityStamps.New(),
            UploadToken = "uploadtk",
            CreatedAtUtc = DateTime.UtcNow
        });
        await fixture.Db.SaveChangesAsync();
        var draftId = await fixture.Manager.EnsureDraftShareAsync(fixture.OwnerId, null, CancellationToken.None);
        using var content = new MemoryStream([1, 2, 3]);
        var staged = await fixture.Manager.StageUploadAsync(fixture.OwnerId, draftId, "f.bin", content.Length, content, CancellationToken.None);
        await fixture.Manager.SealDraftAsync(fixture.OwnerId, draftId, CancellationToken.None);

        await fixture.Job.ProcessAsync(Fixture.Payload(fixture.OwnerId, draftId, staged.UploadId), cts.Token);

        Assert.Equal("completed", fixture.Status.Read(ShareToken)!.State);
        Assert.Single(await fixture.Db.Shares.ToListAsync());
        Assert.False(Directory.Exists(staged.DirectoryPath));
    }

    [Fact]
    public async Task Other_errors_still_mark_the_creation_failed()
    {
        await using var fixture = await Fixture.CreateAsync(onBroadcast: n => { if (n == 2) { throw new InvalidOperationException("boom"); } });

        // The first broadcast is outside the try block, so the failure is raised from the second one.
        await fixture.Job.ProcessAsync(Fixture.Payload(), CancellationToken.None);

        Assert.Equal("failed", fixture.Status.Read(ShareToken)!.State);
    }

    [Fact]
    public async Task A_terminal_failure_releases_the_reserved_link()
    {
        await using var fixture = await Fixture.CreateAsync(onBroadcast: n => { if (n == 2) { throw new InvalidOperationException("boom"); } });
        var payload = Fixture.Payload(fixture.OwnerId);
        await fixture.Manager.ReserveShareTokenAsync(ShareToken, fixture.OwnerId, payload.DraftShareId, CancellationToken.None);

        await fixture.Job.ProcessAsync(payload, CancellationToken.None);

        Assert.Equal("failed", fixture.Status.Read(ShareToken)!.State);
        Assert.Empty(await fixture.Db.ShareTokenReservations.ToListAsync());
    }

    [Fact]
    public async Task Shutdown_before_the_commit_keeps_the_reserved_link_for_the_retry()
    {
        using var cts = new CancellationTokenSource();
        await using var fixture = await Fixture.CreateAsync(onBroadcast: n =>
        {
            if (n == 2)
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
        });
        var payload = Fixture.Payload(fixture.OwnerId);
        await fixture.Manager.ReserveShareTokenAsync(ShareToken, fixture.OwnerId, payload.DraftShareId, CancellationToken.None);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Job.ProcessAsync(payload, cts.Token));

        Assert.Single(await fixture.Db.ShareTokenReservations.ToListAsync());
    }

    [Fact]
    public async Task The_commit_consumes_the_reservation_and_the_owner_gets_the_requested_link()
    {
        await using var fixture = await Fixture.CreateAsync(onBroadcast: _ => { });
        fixture.Db.Users.Add(new UserAccount
        {
            Id = fixture.OwnerId,
            Email = "owner@example.com",
            EmailConfirmed = true,
            PasswordHash = "x:y",
            SecurityStamp = SecurityStamps.New(),
            UploadToken = "uploadtk",
            CreatedAtUtc = DateTime.UtcNow
        });
        await fixture.Db.SaveChangesAsync();
        var draftId = await fixture.Manager.EnsureDraftShareAsync(fixture.OwnerId, null, CancellationToken.None);
        using var content = new MemoryStream([1, 2, 3]);
        var staged = await fixture.Manager.StageUploadAsync(fixture.OwnerId, draftId, "f.bin", content.Length, content, CancellationToken.None);
        await fixture.Manager.SealDraftAsync(fixture.OwnerId, draftId, CancellationToken.None);
        await fixture.Manager.ReserveShareTokenAsync(ShareToken, fixture.OwnerId, draftId, CancellationToken.None);

        await fixture.Job.ProcessAsync(Fixture.Payload(fixture.OwnerId, draftId, staged.UploadId), CancellationToken.None);

        Assert.Equal("completed", fixture.Status.Read(ShareToken)!.State);
        Assert.Equal(ShareToken, Assert.Single(await fixture.Db.Shares.ToListAsync()).ShareToken);
        Assert.Empty(await fixture.Db.ShareTokenReservations.ToListAsync());
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _root;

        public QueuedShareCreationJob Job { get; }
        public ShareCreationStatusStore Status { get; }
        public ShareManager Manager { get; }
        public Guid OwnerId { get; } = Guid.NewGuid();
        public AgoraDbContext Db { get; }

        private Fixture(SqliteConnection connection, string root, QueuedShareCreationJob job, ShareCreationStatusStore status, ShareManager manager, AgoraDbContext db)
        {
            Manager = manager;
            Db = db;
            _connection = connection;
            _root = root;
            Job = job;
            Status = status;
        }

        public static QueuedShareCreationJob.Payload Payload(Guid? ownerId = null, string? draftId = null, string? uploadId = null) => new(
            "owner@example.com", draftId ?? Guid.NewGuid().ToString("N"), ShareToken, null, null, null, null, null, false, null,
            "none", "date", DateTime.UtcNow.AddDays(1), "account_default", null, null, null, null, null, null,
            [uploadId ?? Guid.NewGuid().ToString("N")], ownerId ?? Guid.NewGuid());

        public static async Task<Fixture> CreateAsync(Action<int> onBroadcast)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();

            var root = Path.Combine(Path.GetTempPath(), "agora-shutdown-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var options = Options.Create(new AgoraOptions { StorageRoot = root });
            var objectStore = new FileSystemObjectStore(root);
            var jobs = new NoopJobClient();
            var manager = new ShareManager(
                db,
                options,
                new ShareContentStore(objectStore),
                objectStore,
                jobs,
                new KeyedAsyncLock(),
                new ScratchSpaceMonitor(options.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System),
                NullLogger<ShareManager>.Instance);

            var status = new ShareCreationStatusStore(options);
            var broadcaster = new ShareProgressBroadcaster(new FakeHub(onBroadcast));
            var job = new QueuedShareCreationJob(
                manager, db, jobs, new NoopEmailSender(), status, broadcaster, new FixedOrigin(),
                options, Options.Create(new EmailSenderOptions()), NullLogger<QueuedShareCreationJob>.Instance);
            return new Fixture(connection, root, job, status, manager, db);
        }

        public async ValueTask DisposeAsync()
        {
            await _connection.DisposeAsync();
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    private sealed class NoopJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FixedOrigin : IPublicOriginProvider
    {
        public string? ConfiguredOrigin => "https://files.example.com";
    }

    // Reports each broadcast by number (the first, "processing", happens outside the job's try block).
    private sealed class FakeHub(Action<int> onBroadcast) : IHubContext<ShareProgressHub>
    {
        public IHubClients Clients { get; } = new FakeClients(onBroadcast);
        public IGroupManager Groups => throw new NotSupportedException();
    }

    private sealed class FakeClients(Action<int> onBroadcast) : IHubClients, IClientProxy
    {
        private int _calls;

        public IClientProxy Group(string groupName) => this;

        public Task SendCoreAsync(string method, object?[] args, CancellationToken cancellationToken = default)
        {
            onBroadcast(Interlocked.Increment(ref _calls));

            return Task.CompletedTask;
        }

        public IClientProxy All => this;
        public IClientProxy AllExcept(IReadOnlyList<string> excludedConnectionIds) => this;
        public IClientProxy Client(string connectionId) => this;
        public IClientProxy Clients(IReadOnlyList<string> connectionIds) => this;
        public IClientProxy GroupExcept(string groupName, IReadOnlyList<string> excludedConnectionIds) => this;
        public IClientProxy Groups(IReadOnlyList<string> groupNames) => this;
        public IClientProxy User(string userId) => this;
        public IClientProxy Users(IReadOnlyList<string> userIds) => this;
    }
}
