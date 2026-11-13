using Agora.Application.Utilities;
using Agora.Application.Models;
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

/// <summary>The link-claim steps of the create-share endpoint: what a refused, repeated or failed submission leaves behind.</summary>
public sealed class ShareSubmissionTests
{
    private const string Token = "pending_link";
    private static readonly Guid OwnerId = Guid.NewGuid();
    private static readonly Guid OtherId = Guid.NewGuid();

    [Fact]
    public async Task A_409_keeps_the_claim_a_concurrent_submission_relies_on()
    {
        await using var f = await Fixture.CreateAsync();
        var draft = await f.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        // The concurrent submission of the same draft and link: it holds the claim and seals the draft first.
        await f.Manager.ReserveShareTokenAsync(Token, OwnerId, draft, CancellationToken.None);
        await f.Manager.SealDraftAsync(OwnerId, draft, CancellationToken.None);

        var result = await ShareSubmission.ClaimAndSealAsync(f.Manager, Token, OwnerId, draft, () => Task.CompletedTask, CancellationToken.None);

        Assert.False(result.Refused);
        Assert.False(result.Sealed);
        Assert.Single(await f.Db.ShareTokenReservations.ToListAsync());
    }

    [Fact]
    public async Task A_409_after_this_request_inserted_the_claim_still_keeps_it()
    {
        await using var f = await Fixture.CreateAsync();
        var draft = await f.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        await f.Manager.SealDraftAsync(OwnerId, draft, CancellationToken.None);

        var result = await ShareSubmission.ClaimAndSealAsync(f.Manager, Token, OwnerId, draft, () => Task.CompletedTask, CancellationToken.None);

        Assert.False(result.Sealed);
        Assert.Single(await f.Db.ShareTokenReservations.ToListAsync());
    }

    [Fact]
    public async Task A_failed_enqueue_releases_the_claim_this_request_made()
    {
        await using var f = await Fixture.CreateAsync();
        var draft = await f.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        await Assert.ThrowsAsync<UploadLimitException>(() => ShareSubmission.ClaimAndSealAsync(
            f.Manager, Token, OwnerId, draft, () => throw new InvalidOperationException("queue down"), CancellationToken.None));

        Assert.Empty(await f.Db.ShareTokenReservations.ToListAsync());
        Assert.False(f.Manager.IsDraftSealed(draft));
    }

    [Fact]
    public async Task A_successful_submission_holds_the_claim_and_refuses_another_owner()
    {
        await using var f = await Fixture.CreateAsync();
        var draft = await f.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        var result = await ShareSubmission.ClaimAndSealAsync(f.Manager, Token, OwnerId, draft, () => Task.CompletedTask, CancellationToken.None);
        Assert.True(result.Sealed);

        var otherDraft = await f.Manager.EnsureDraftShareAsync(OtherId, null, CancellationToken.None);
        var refused = await ShareSubmission.ClaimAndSealAsync(f.Manager, Token, OtherId, otherDraft, () => Task.CompletedTask, CancellationToken.None);
        Assert.True(refused.Refused);
        Assert.StartsWith("That share link is already in use.", refused.Text);
        Assert.False(f.Manager.IsDraftSealed(otherDraft));
    }

    [Fact]
    public async Task Another_owners_in_flight_status_entry_refuses_the_link_until_it_is_terminal()
    {
        await using var f = await Fixture.CreateAsync();
        f.Status.MarkQueued(Token, OtherId, "job1");

        var refusal = await ShareSubmission.RefuseRequestedTokenAsync(f.Manager, f.Status, Token, OwnerId, "draft0", CancellationToken.None);
        Assert.StartsWith("That share link is already in use.", refusal);
        // The entry's own owner is not refused by it.
        Assert.Null(await ShareSubmission.RefuseRequestedTokenAsync(f.Manager, f.Status, Token, OtherId, "draft0", CancellationToken.None));

        f.Status.MarkFailed(Token, "failed");
        Assert.Null(await ShareSubmission.RefuseRequestedTokenAsync(f.Manager, f.Status, Token, OwnerId, "draft0", CancellationToken.None));
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _root;

        public ShareManager Manager { get; }
        public AgoraDbContext Db { get; }
        public ShareCreationStatusStore Status { get; }

        private Fixture(SqliteConnection connection, string root, ShareManager manager, AgoraDbContext db, ShareCreationStatusStore status)
        {
            _connection = connection;
            _root = root;
            Manager = manager;
            Db = db;
            Status = status;
        }

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var root = Path.Combine(Path.GetTempPath(), "agora-submission-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var options = Options.Create(new AgoraOptions { StorageRoot = root });
            var objectStore = new FileSystemObjectStore(root);
            var manager = new ShareManager(
                db, options, new ShareContentStore(objectStore), objectStore, new NoopJobClient(), new KeyedAsyncLock(),
                new ScratchSpaceMonitor(options.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System),
                NullLogger<ShareManager>.Instance);
            return new Fixture(connection, root, manager, db, new ShareCreationStatusStore(options));
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
}
