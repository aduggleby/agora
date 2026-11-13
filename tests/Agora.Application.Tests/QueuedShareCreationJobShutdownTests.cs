using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
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
        await using var fixture = await Fixture.CreateAsync(onSecondBroadcast: () =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Job.ProcessAsync(Fixture.Payload(), cts.Token));

        var entry = fixture.Status.Read(ShareToken);
        Assert.NotNull(entry);
        Assert.NotEqual("failed", entry.State);
    }

    [Fact]
    public async Task Other_errors_still_mark_the_creation_failed()
    {
        await using var fixture = await Fixture.CreateAsync(onSecondBroadcast: () => throw new InvalidOperationException("boom"));

        // The first broadcast is outside the try block, so the failure is raised from the second one.
        await fixture.Job.ProcessAsync(Fixture.Payload(), CancellationToken.None);

        Assert.Equal("failed", fixture.Status.Read(ShareToken)!.State);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _root;

        public QueuedShareCreationJob Job { get; }
        public ShareCreationStatusStore Status { get; }

        private Fixture(SqliteConnection connection, string root, QueuedShareCreationJob job, ShareCreationStatusStore status)
        {
            _connection = connection;
            _root = root;
            Job = job;
            Status = status;
        }

        public static QueuedShareCreationJob.Payload Payload() => new(
            "owner@example.com", Guid.NewGuid().ToString("N"), ShareToken, null, null, null, null, null, false, null,
            "none", "date", DateTime.UtcNow.AddDays(1), "account_default", null, null, null, null, null, null,
            [Guid.NewGuid().ToString("N")], Guid.NewGuid());

        public static async Task<Fixture> CreateAsync(Action onSecondBroadcast)
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
            var broadcaster = new ShareProgressBroadcaster(new FakeHub(onSecondBroadcast));
            var job = new QueuedShareCreationJob(
                manager, db, jobs, new NoopEmailSender(), status, broadcaster, new FixedOrigin(),
                options, Options.Create(new EmailSenderOptions()), NullLogger<QueuedShareCreationJob>.Instance);
            return new Fixture(connection, root, job, status);
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

    // Runs the callback on the second broadcast (the first, "processing", happens outside the job's try block).
    private sealed class FakeHub(Action onSecondBroadcast) : IHubContext<ShareProgressHub>
    {
        public IHubClients Clients { get; } = new FakeClients(onSecondBroadcast);
        public IGroupManager Groups => throw new NotSupportedException();
    }

    private sealed class FakeClients(Action onSecondBroadcast) : IHubClients, IClientProxy
    {
        private int _calls;

        public IClientProxy Group(string groupName) => this;

        public Task SendCoreAsync(string method, object?[] args, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _calls) == 2)
            {
                onSecondBroadcast();
            }

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
