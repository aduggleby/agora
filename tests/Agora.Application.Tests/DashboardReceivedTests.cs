using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>Dashboard lists, batch re-enable, the "new received" marker and the received history.</summary>
public sealed class DashboardReceivedTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();
    private static readonly Guid OtherId = Guid.NewGuid();
    private const string OwnerEmail = "dash-owner@example.com";
    private const string OtherEmail = "dash-other@example.com";

    [Fact]
    public async Task ReenableSharesFor24HoursAsync_ReenablesOnlyExpiredOrdinaryOwnShares()
    {
        await using var harness = await Harness.CreateAsync();
        var expired = await harness.AddShareAsync(OwnerId, expiresInMinutes: -5);
        var expiredToo = await harness.AddShareAsync(OwnerId, expiresInMinutes: -60);
        var active = await harness.AddShareAsync(OwnerId, expiresInMinutes: 600);
        var direct = await harness.AddShareAsync(OwnerId, expiresInMinutes: -5, accessMode: "direct_link");
        var foreign = await harness.AddShareAsync(OtherId, expiresInMinutes: -5);
        var missingArchive = await harness.AddShareAsync(OwnerId, expiresInMinutes: -5, withArchive: false);
        var before = DateTime.UtcNow;

        var count = await harness.Manager.ReenableSharesFor24HoursAsync(
            [expired.Id, expiredToo.Id, active.Id, direct.Id, foreign.Id, missingArchive.Id, Guid.NewGuid(), expired.Id],
            ShareOwner.For(OwnerId, OwnerEmail),
            CancellationToken.None);

        Assert.Equal(2, count);
        var byId = await harness.Db.Shares.AsNoTracking().ToDictionaryAsync(x => x.Id);
        Assert.InRange(byId[expired.Id].ExpiresAtUtc!.Value, before.AddHours(23), before.AddHours(25));
        Assert.InRange(byId[expiredToo.Id].ExpiresAtUtc!.Value, before.AddHours(23), before.AddHours(25));
        Assert.True(byId[active.Id].ExpiresAtUtc > before.AddHours(9));
        Assert.True(byId[direct.Id].ExpiresAtUtc < before);
        Assert.True(byId[foreign.Id].ExpiresAtUtc < before);
        Assert.True(byId[missingArchive.Id].ExpiresAtUtc < before);
    }

    [Fact]
    public async Task ReenableSharesFor24HoursAsync_RefusesMoreThanTheBatchCap()
    {
        await using var harness = await Harness.CreateAsync();
        var ids = Enumerable.Range(0, ShareManager.MaxBatchDeleteShares + 1).Select(_ => Guid.NewGuid()).ToArray();

        Assert.Null(await harness.Manager.ReenableSharesFor24HoursAsync(ids, ShareOwner.For(OwnerId, OwnerEmail), CancellationToken.None));
    }

    [Fact]
    public void IsNewReceived_TreatsNeverOpenedAsAllNewAndComparesCreationTime()
    {
        var seen = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

        Assert.True(ShareManager.IsNewReceived(seen.AddYears(-1), null));
        Assert.True(ShareManager.IsNewReceived(seen.AddSeconds(1), seen));
        Assert.False(ShareManager.IsNewReceived(seen, seen));
        Assert.False(ShareManager.IsNewReceived(seen.AddMinutes(-1), seen));
    }

    [Fact]
    public async Task MarkReceivedSeenAsync_SetsTheTimestampForThatUserOnly()
    {
        await using var harness = await Harness.CreateAsync();
        Assert.Null(await harness.Manager.GetReceivedSeenAtUtcAsync(OwnerId, CancellationToken.None));
        var before = DateTime.UtcNow;

        await harness.Manager.MarkReceivedSeenAsync(OwnerId, null, CancellationToken.None);

        var seen = await harness.Manager.GetReceivedSeenAtUtcAsync(OwnerId, CancellationToken.None);
        Assert.NotNull(seen);
        Assert.InRange(seen!.Value, before, DateTime.UtcNow);
        Assert.Null(await harness.Manager.GetReceivedSeenAtUtcAsync(OtherId, CancellationToken.None));
        // An unknown user is ignored.
        await harness.Manager.MarkReceivedSeenAsync(Guid.NewGuid(), null, CancellationToken.None);
    }

    [Fact]
    public async Task MarkReceivedSeenAsync_StoresTheNewestShownTimeAndNeverMovesBackOrIntoTheFuture()
    {
        await using var harness = await Harness.CreateAsync();
        var rendered = DateTime.UtcNow.AddMinutes(-10);

        await harness.Manager.MarkReceivedSeenAsync(OwnerId, rendered, CancellationToken.None);
        Assert.Equal(rendered, await harness.Manager.GetReceivedSeenAtUtcAsync(OwnerId, CancellationToken.None));

        // An older render time (a stale tab) does not move the marker back.
        await harness.Manager.MarkReceivedSeenAsync(OwnerId, rendered.AddMinutes(-5), CancellationToken.None);
        Assert.Equal(rendered, await harness.Manager.GetReceivedSeenAtUtcAsync(OwnerId, CancellationToken.None));

        // A render time in the future is capped at now.
        await harness.Manager.MarkReceivedSeenAsync(OwnerId, DateTime.UtcNow.AddDays(1), CancellationToken.None);
        Assert.True(await harness.Manager.GetReceivedSeenAtUtcAsync(OwnerId, CancellationToken.None) <= DateTime.UtcNow);
    }

    [Fact]
    public async Task ListOwnAndReceivedShares_SplitBySenderAndLimitEachListSeparately()
    {
        await using var harness = await Harness.CreateAsync();
        var owner = ShareOwner.For(OwnerId, OwnerEmail);
        var received = await harness.AddShareAsync(OwnerId, expiresInMinutes: 60, senderEmail: "sender@example.com", ageMinutes: 500);
        for (var i = 0; i < 3; i++)
        {
            await harness.AddShareAsync(OwnerId, expiresInMinutes: 60, ageMinutes: i);
        }

        var own = await harness.Manager.ListOwnSharesAsync(owner, 2, CancellationToken.None);
        var receivedList = await harness.Manager.ListReceivedSharesAsync(owner, 2, CancellationToken.None);

        // Own shares never push received ones out of their list.
        Assert.Equal(2, own.Count);
        Assert.All(own, x => Assert.Null(x.SenderEmail));
        Assert.Equal(received.Id, Assert.Single(receivedList).ShareId);
        Assert.Equal(received.ShareToken, receivedList[0].ShareToken);
    }

    [Fact]
    public async Task ListReceivedHistoryAsync_IncludesDeletedAndExpiredExcludesOwnAndForeignAndPages()
    {
        await using var harness = await Harness.CreateAsync();
        var owner = ShareOwner.For(OwnerId, OwnerEmail);
        var live = await harness.AddShareAsync(OwnerId, expiresInMinutes: 60, senderEmail: "a@example.com", ageMinutes: 1);
        var expired = await harness.AddShareAsync(OwnerId, expiresInMinutes: -60, senderEmail: "b@example.com", ageMinutes: 2);
        var deleted = await harness.AddShareAsync(OwnerId, expiresInMinutes: 60, senderEmail: "c@example.com", ageMinutes: 3);
        deleted.DeletedAtUtc = DateTime.UtcNow;
        await harness.AddShareAsync(OwnerId, expiresInMinutes: 60, ageMinutes: 4);
        await harness.AddShareAsync(OtherId, expiresInMinutes: 60, senderEmail: "d@example.com", ageMinutes: 5);
        await harness.Db.SaveChangesAsync();

        var all = await harness.Manager.ListReceivedHistoryAsync(owner, 0, 50, CancellationToken.None);
        Assert.Equal([live.Id, expired.Id, deleted.Id], all.Select(x => x.ShareId).ToArray());
        Assert.NotNull(all[2].DeletedAtUtc);

        var first = await harness.Manager.ListReceivedHistoryAsync(owner, 0, 2, CancellationToken.None);
        var second = await harness.Manager.ListReceivedHistoryAsync(owner, 2, 2, CancellationToken.None);
        Assert.Equal([live.Id, expired.Id], first.Select(x => x.ShareId).ToArray());
        Assert.Equal([deleted.Id], second.Select(x => x.ShareId).ToArray());

        // The dashboard list still hides the deleted one.
        Assert.DoesNotContain(await harness.Manager.ListReceivedSharesAsync(owner, 100, CancellationToken.None), x => x.ShareId == deleted.Id);
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        public AgoraDbContext Db { get; }
        public ShareManager Manager { get; }
        public FileSystemObjectStore ObjectStore { get; }
        private string StorageRoot { get; }

        private Harness(SqliteConnection connection, string storageRoot, AgoraDbContext db, ShareManager manager, FileSystemObjectStore objectStore)
        {
            _connection = connection;
            StorageRoot = storageRoot;
            Db = db;
            Manager = manager;
            ObjectStore = objectStore;
        }

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(TestUsers.Seed(OwnerId, OwnerEmail));
            db.Users.Add(TestUsers.Seed(OtherId, OtherEmail));
            await db.SaveChangesAsync();

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-dashboard-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var appOptions = Options.Create(new AgoraOptions { StorageRoot = storageRoot });
            var objectStore = new FileSystemObjectStore(storageRoot);
            var manager = new ShareManager(
                db,
                appOptions,
                new ShareContentStore(objectStore),
                objectStore,
                new NoopBackgroundJobClient(),
                new KeyedAsyncLock(),
                new ScratchSpaceMonitor(appOptions.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System),
                NullLogger<ShareManager>.Instance);

            return new Harness(connection, storageRoot, db, manager, objectStore);
        }

        public async Task<Share> AddShareAsync(
            Guid ownerId,
            int expiresInMinutes,
            string accessMode = "download_only",
            string? senderEmail = null,
            int ageMinutes = 0,
            bool withArchive = true)
        {
            var key = $"zips/2026/11/{Guid.NewGuid():N}.zip";
            if (withArchive)
            {
                await ObjectStore.PutBytesAsync(key, "zip"u8.ToArray(), "application/zip", CancellationToken.None);
            }

            var share = new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerId,
                UploaderEmail = ownerId == OwnerId ? OwnerEmail : OtherEmail,
                ShareToken = Guid.NewGuid().ToString("N")[..8],
                ZipDisplayName = "files.zip",
                ZipDiskPath = withArchive ? key : string.Empty,
                ZipSizeBytes = 1,
                NotifyMode = "none",
                ShareExperienceType = "archive",
                AccessMode = accessMode,
                SenderEmail = senderEmail,
                SenderName = senderEmail is null ? null : "Sender",
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(expiresInMinutes),
                CreatedAtUtc = DateTime.UtcNow.AddMinutes(-ageMinutes)
            };
            Db.Shares.Add(share);
            await Db.SaveChangesAsync();
            return share;
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(StorageRoot))
            {
                Directory.Delete(StorageRoot, recursive: true);
            }
        }
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
