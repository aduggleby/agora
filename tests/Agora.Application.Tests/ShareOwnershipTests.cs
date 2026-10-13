using Agora.Application.Abstractions;
using Agora.Application.Constants;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
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

/// <summary>
/// Shares and account templates are owned by user id and nothing else: the uploader address is display data, a row
/// without an owner id belongs to nobody, and a later account registered under the same address never sees rows of
/// an earlier one.
/// </summary>
public sealed class ShareOwnershipTests
{
    private const string Email = "owner@example.com";

    [Fact]
    public async Task Rows_match_by_owner_id_only()
    {
        await using var harness = await Harness.CreateAsync();
        var ownerId = Guid.NewGuid();
        var byId = harness.AddShare(ownerId, Email, "by-id");
        harness.AddShare(null, Email, "unowned");
        harness.AddShare(Guid.NewGuid(), Email, "previous-owner");
        await harness.Db.SaveChangesAsync();

        var current = (await harness.Manager.ListRecentSharesForUploaderAsync(ShareOwner.For(ownerId, Email), 10, CancellationToken.None))
            .Select(x => x.ShareId).ToList();
        Assert.Equal([byId.Id], current);

        // The id still matches after an email change.
        var renamed = (await harness.Manager.ListRecentSharesForUploaderAsync(ShareOwner.For(ownerId, "renamed@example.com"), 10, CancellationToken.None))
            .Select(x => x.ShareId).ToList();
        Assert.Equal([byId.Id], renamed);

        // A newcomer registered under the address sees nothing: neither the unowned row nor the previous owner's.
        Assert.Empty(await harness.Manager.ListRecentSharesForUploaderAsync(ShareOwner.For(Guid.NewGuid(), Email), 10, CancellationToken.None));
    }

    [Fact]
    public async Task Mutations_refuse_shares_of_another_id_with_the_same_address()
    {
        await using var harness = await Harness.CreateAsync();
        var share = harness.AddShare(Guid.NewGuid(), Email, "owned");
        var unowned = harness.AddShare(null, Email, "unowned");
        await harness.Db.SaveChangesAsync();
        var newcomer = ShareOwner.For(Guid.NewGuid(), Email);

        foreach (var id in new[] { share.Id, unowned.Id })
        {
            Assert.False(await harness.Manager.DeleteShareAsync(id, newcomer, CancellationToken.None));
            Assert.False(await harness.Manager.ReenableShareFor24HoursAsync(id, newcomer, CancellationToken.None));
            Assert.Null(await harness.Manager.GetCopyableShareTokenAsync(id, newcomer, CancellationToken.None));
        }

        Assert.Null(await harness.Manager.FindByTokenForUploaderAsync("owned", newcomer, CancellationToken.None));
        Assert.Null(await harness.Manager.FindByTokenForUploaderAsync("unowned", newcomer, CancellationToken.None));
        Assert.Equal(0, await harness.Db.Shares.CountAsync(x => x.DeletedAtUtc != null));

        var owner = ShareOwner.For(share.OwnerUserId!.Value, "changed@example.com");
        Assert.Equal("owned", await harness.Manager.GetCopyableShareTokenAsync(share.Id, owner, CancellationToken.None));
        Assert.True(await harness.Manager.DeleteShareAsync(share.Id, owner, CancellationToken.None));
    }

    [Fact]
    public async Task CreateShareAsync_stamps_the_owner_from_the_command()
    {
        await using var harness = await Harness.CreateAsync();
        var ownerId = harness.AddUser(Email).Id;
        await harness.Db.SaveChangesAsync();

        var created = await harness.Manager.CreateShareAsync(await harness.CommandAsync("Owner@Example.com", ownerId), CancellationToken.None);

        var row = await harness.Db.Shares.AsNoTracking().SingleAsync(x => x.Id == created.ShareId);
        Assert.Equal(ownerId, row.OwnerUserId);
        Assert.Equal(Email, row.UploaderEmail);
    }

    [Fact]
    public async Task Share_creation_waits_for_the_owner_lock_and_is_refused_once_the_account_is_deleted()
    {
        await using var harness = await Harness.CreateAsync();
        var user = harness.AddUser(Email);
        await harness.Db.SaveChangesAsync();
        var command = await harness.CommandAsync(Email, user.Id);

        // Creation cannot slip in while the owner lock is held (deletion holds it around its snapshot and delete).
        Task creation;
        using (await harness.Locks.LockAsync(ShareManager.OwnerLockKey(user.Id), CancellationToken.None))
        {
            creation = harness.Manager.CreateShareAsync(command, CancellationToken.None);
            try
            {
                await Task.Delay(200);
                Assert.False(creation.IsCompleted);
            }
            catch
            {
                // Release the lock (end of the using block) and observe the task before failing the test.
                _ = creation.ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
                throw;
            }
        }

        await creation;
        Assert.Equal(1, await harness.Db.Shares.CountAsync());

        // Once the account is gone, a queued creation is refused and leaves nothing durable behind.
        Assert.True(await harness.Auth.DeleteUserAsync(user.Id, CancellationToken.None));
        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.Manager.CreateShareAsync(harness.CommandAsync(Email, user.Id).Result, CancellationToken.None));
        Assert.Contains("no longer exists", refused.Message);
        Assert.Equal(1, await harness.Db.Shares.CountAsync());
        // Exactly the first share's archive remains in the store; the refused creation's objects were removed again.
        var durable = harness.DurableFiles();
        Assert.Single(durable.Where(path => path.Contains($"{Path.DirectorySeparatorChar}zips{Path.DirectorySeparatorChar}", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Drafts_are_authorized_by_owner_id_and_legacy_records_belong_to_nobody()
    {
        await using var harness = await Harness.CreateAsync();
        var ownerId = Guid.NewGuid();
        var draftId = await harness.Manager.EnsureDraftShareAsync(ownerId, null, CancellationToken.None);

        // Another account cannot see or seal the draft.
        Assert.Empty(await harness.Manager.ListStagedUploadsForDraftAsync(Guid.NewGuid(), draftId, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Manager.SealDraftAsync(Guid.NewGuid(), draftId, CancellationToken.None));

        // A draft written before owner ids existed carries no id and is usable by nobody, including its old address.
        var draftPath = Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId, "draft.json");
        var legacy = System.Text.Json.JsonSerializer.Serialize(new
        {
            DraftShareId = draftId,
            UploaderEmail = Email,
            LastActivityUtc = DateTime.UtcNow,
            TemplateMode = "account_default",
            Title = "",
            H1 = "",
            Description = ""
        });
        await File.WriteAllTextAsync(draftPath, legacy);
        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Manager.SealDraftAsync(ownerId, draftId, CancellationToken.None));
        Assert.Empty(await harness.Manager.ListStagedUploadsForDraftAsync(ownerId, draftId, CancellationToken.None));
        var refused = await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.StageUploadAsync(ownerId, draftId, "a.txt", 1, new MemoryStream([1]), CancellationToken.None));
        Assert.Equal(UploadLimitKind.DraftClosed, refused.Kind);
    }

    [Fact]
    public async Task Received_share_quota_is_counted_per_owner_id()
    {
        await using var harness = await Harness.CreateAsync();
        var ownerId = Guid.NewGuid();
        var now = DateTime.UtcNow;
        harness.AddShare(ownerId, Email, "r1", sender: true, createdAtUtc: now.AddHours(-1), bytes: 100);
        harness.AddShare(ownerId, "old-address@example.com", "r2", sender: true, createdAtUtc: now.AddHours(-1), bytes: 50);
        harness.AddShare(Guid.NewGuid(), Email, "r3", sender: true, createdAtUtc: now.AddHours(-1), bytes: 1000);
        harness.AddShare(null, Email, "r4", sender: true, createdAtUtc: now.AddHours(-1), bytes: 1000);
        await harness.Db.SaveChangesAsync();

        var usage = await harness.Manager.GetReceivedShareUsageAsync(ShareOwner.For(ownerId, Email), now.AddHours(-24), CancellationToken.None);

        Assert.Equal(new ShareManager.ReceivedShareUsage(2, 150), usage);
    }

    [Fact]
    public async Task Account_template_follows_the_id_and_is_never_reached_by_address()
    {
        await using var harness = await Harness.CreateAsync();
        var ownerId = Guid.NewGuid();
        harness.Db.AccountTemplates.Add(new AccountTemplate { Id = Guid.NewGuid(), OwnerUserId = null, UploaderEmail = Email, Title = "Unowned", UpdatedAtUtc = DateTime.UtcNow });
        await harness.Db.SaveChangesAsync();
        var owner = ShareOwner.For(ownerId, "current@example.com");

        // The unowned row at the same address is not the owner's; the default is served instead.
        Assert.Equal($"by {Email}", (await harness.Manager.GetAccountTemplateAsync(ShareOwner.For(ownerId, Email), CancellationToken.None)).Title);

        await harness.Manager.UpsertAccountTemplateAsync(owner, new ShareTemplateData("Mine", "H1", "D", null, null, "center"), CancellationToken.None);

        var rows = await harness.Db.AccountTemplates.AsNoTracking().ToListAsync();
        Assert.Equal(2, rows.Count);
        Assert.Equal("Mine", rows.Single(x => x.OwnerUserId == ownerId).Title);
        Assert.Equal("Mine", (await harness.Manager.GetAccountTemplateAsync(ShareOwner.For(ownerId, "renamed@example.com"), CancellationToken.None)).Title);
        Assert.Equal($"by {Email}", (await harness.Manager.GetAccountTemplateAsync(ShareOwner.For(Guid.NewGuid(), Email), CancellationToken.None)).Title);
    }

    [Fact]
    public async Task OwnerBackfill_runs_once_then_only_counts_the_quarantine()
    {
        await using var harness = await Harness.CreateAsync();
        var user = harness.AddUser(Email);
        var mixedCase = harness.AddShare(null, "Owner@Example.com", "mixed");
        var exact = harness.AddShare(null, Email, "exact");
        var orphan = harness.AddShare(null, "gone@example.com", "orphan");
        var otherId = Guid.NewGuid();
        var alreadyOwned = harness.AddShare(otherId, Email, "already-owned");
        var template = new AccountTemplate { Id = Guid.NewGuid(), UploaderEmail = "OWNER@example.com", UpdatedAtUtc = DateTime.UtcNow };
        var orphanTemplate = new AccountTemplate { Id = Guid.NewGuid(), UploaderEmail = "gone@example.com", UpdatedAtUtc = DateTime.UtcNow };
        harness.Db.AccountTemplates.AddRange(template, orphanTemplate);
        await harness.Db.SaveChangesAsync();
        harness.Db.ChangeTracker.Clear();

        var first = await OwnerBackfill.RunAsync(harness.Db, CancellationToken.None);
        Assert.Equal(new OwnerBackfill.Result(false, 2, 1, 1, 1), first);

        var shares = await harness.Db.Shares.AsNoTracking().ToDictionaryAsync(x => x.Id, x => x.OwnerUserId);
        Assert.Equal(user.Id, shares[mixedCase.Id]);
        Assert.Equal(user.Id, shares[exact.Id]);
        Assert.Null(shares[orphan.Id]);
        Assert.Equal(otherId, shares[alreadyOwned.Id]);
        var templates = await harness.Db.AccountTemplates.AsNoTracking().ToDictionaryAsync(x => x.Id, x => x.OwnerUserId);
        Assert.Equal(user.Id, templates[template.Id]);
        Assert.Null(templates[orphanTemplate.Id]);
        Assert.True(await harness.Db.SystemSettings.AnyAsync(x => x.Key == SystemSettingKeys.OwnershipBackfillCompletedAt));

        // Completed: a null row created afterwards (even one whose address matches an account) is never assigned.
        var late = harness.AddShare(null, Email, "late");
        await harness.Db.SaveChangesAsync();
        harness.Db.ChangeTracker.Clear();
        var second = await OwnerBackfill.RunAsync(harness.Db, CancellationToken.None);
        Assert.Equal(new OwnerBackfill.Result(true, 0, 0, 2, 1), second);
        Assert.Null((await harness.Db.Shares.AsNoTracking().SingleAsync(x => x.Id == late.Id)).OwnerUserId);
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _storageRoot;

        public AgoraDbContext Db { get; }
        public ShareManager Manager { get; }
        public AuthService Auth { get; }
        public KeyedAsyncLock Locks { get; }
        public string StorageRoot => _storageRoot;

        private Harness(SqliteConnection connection, string storageRoot, AgoraDbContext db, ShareManager manager, KeyedAsyncLock locks)
        {
            _connection = connection;
            _storageRoot = storageRoot;
            Db = db;
            Manager = manager;
            Locks = locks;
            Auth = new AuthService(db, new NoopEmailSender(), ownerLocks: locks);
        }

        /// <summary>Every durable object currently in the file-system store (archives and share content).</summary>
        public List<string> DurableFiles() =>
            new[] { "zips", "shares" }
                .Select(x => Path.Combine(_storageRoot, x))
                .Where(Directory.Exists)
                .SelectMany(x => Directory.EnumerateFiles(x, "*", SearchOption.AllDirectories))
                .ToList();

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-ownership-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = Options.Create(new AgoraOptions { StorageRoot = storageRoot });
            var objectStore = new FileSystemObjectStore(storageRoot);
            var scratch = new ScratchSpaceMonitor(options.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
            var locks = new KeyedAsyncLock();
            var manager = new ShareManager(
                db,
                options,
                new ShareContentStore(objectStore),
                objectStore,
                new NoopBackgroundJobClient(),
                locks,
                scratch,
                NullLogger<ShareManager>.Instance);
            return new Harness(connection, storageRoot, db, manager, locks);
        }

        public UserAccount AddUser(string email)
        {
            var user = new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = EmailAddress.Normalize(email),
                EmailConfirmed = true,
                PasswordHash = "x:y",
                SecurityStamp = SecurityStamps.New(),
                UploadToken = Guid.NewGuid().ToString("N")[..8],
                CreatedAtUtc = DateTime.UtcNow
            };
            Db.Users.Add(user);
            return user;
        }

        public Share AddShare(Guid? ownerUserId, string uploaderEmail, string token, bool sender = false, DateTime? createdAtUtc = null, long bytes = 1)
        {
            var share = new Share
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerUserId,
                UploaderEmail = uploaderEmail,
                ShareToken = token,
                ZipDisplayName = "files.zip",
                ZipDiskPath = "zips/2026/10/x.zip",
                ZipSizeBytes = bytes,
                NotifyMode = "none",
                SenderName = sender ? "Sender" : null,
                SenderEmail = sender ? "sender@example.com" : null,
                CreatedAtUtc = createdAtUtc ?? DateTime.UtcNow,
                Files =
                [
                    new ShareFile
                    {
                        Id = Guid.NewGuid(),
                        OriginalFilename = "f.bin",
                        StoredRelativePath = "shares/x/f.bin",
                        RenderType = "binary",
                        OriginalSizeBytes = bytes,
                        DetectedContentType = "application/octet-stream"
                    }
                ]
            };
            Db.Shares.Add(share);
            return share;
        }

        public async Task<CreateShareCommand> CommandAsync(string uploaderEmail, Guid ownerUserId)
        {
            var path = Path.Combine(_storageRoot, $"{Guid.NewGuid():N}-hello.txt");
            await File.WriteAllTextAsync(path, "hello");
            return new CreateShareCommand
            {
                UploaderEmail = uploaderEmail,
                OwnerUserId = ownerUserId,
                ExpiryMode = ExpiryMode.Indefinite,
                NotifyMode = "none",
                TemplateMode = TemplateMode.PerUpload,
                Files = [new UploadSourceFile(path, "hello.txt", 5, "text/plain")]
            };
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(_storageRoot))
            {
                Directory.Delete(_storageRoot, recursive: true);
            }
        }
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
