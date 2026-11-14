using Agora.Application.Abstractions;
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
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Agora.Application.Tests;

/// <summary>
/// Starts one PostgreSQL container for all tests in <see cref="PostgresIntegrationTests"/>.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _container;

    /// <summary>Why the tests are skipped (Docker unavailable), or null.</summary>
    public string? UnavailableReason { get; private set; }

    public async Task InitializeAsync()
    {
        try
        {
            _container = new PostgreSqlBuilder("postgres:17-alpine").Build();
            await _container.StartAsync();
        }
        catch (Exception ex)
        {
            UnavailableReason = $"PostgreSQL test container unavailable (Docker required): {ex.Message}";
        }
    }

    /// <summary>Connection string for a new, not yet existing database on the shared server.</summary>
    public string NewDatabaseConnectionString() =>
        new NpgsqlConnectionStringBuilder(_container!.GetConnectionString())
        {
            Database = $"agora_test_{Guid.NewGuid():N}"
        }.ToString();

    public async Task DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}

/// <summary>
/// Integration tests against a real PostgreSQL 17 (Testcontainers; skipped without Docker, failed instead when
/// AGORA_REQUIRE_POSTGRES_TESTS=1). Each test gets its own database, migrated with the PostgreSQL migration set
/// exactly as at startup. Covers behaviour SQLite cannot: case-sensitive comparisons, timestamptz UTC rules,
/// unique-violation error shapes, conditional ExecuteUpdate and the Hangfire.PostgreSql schema.
/// </summary>
public sealed class PostgresIntegrationTests(PostgresFixture fixture) : IClassFixture<PostgresFixture>
{
    [SkippableFact]
    public async Task Migrations_apply_to_an_empty_database()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();

        Assert.IsType<PostgresAgoraDbContext>(db);
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        Assert.Contains(await db.Database.GetAppliedMigrationsAsync(), m => m.EndsWith("_InitialPostgres", StringComparison.Ordinal));
    }

    [SkippableFact]
    public async Task Agent_access_columns_round_trip_and_agent_listing_filters_by_token()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        var user = TestUsers.Seed(Guid.NewGuid(), "agent.user@example.com");
        db.Users.Add(user);
        var tokenId = Guid.NewGuid();
        var byAgent = NewShare("agent-made", DateTime.UtcNow.AddMinutes(-1));
        byAgent.OwnerUserId = user.Id;
        byAgent.CreatedByApiTokenId = tokenId;
        byAgent.SentByAgent = true;
        var plain = NewShare("browser-made", DateTime.UtcNow);
        plain.OwnerUserId = user.Id;
        db.Shares.AddRange(byAgent, plain);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var service = new ApiTokenService(db);
        var agentToken = await service.CreateAgentTokenAsync(user.Id, user.SecurityStamp, "bot", ApiTokens.AccessLevels.All, CancellationToken.None);
        Assert.Equal("all", (await service.ValidateAsync(agentToken, CancellationToken.None))!.AccessLevel);
        var auth = new AuthService(db, new NoopEmailSender());
        Assert.False(await auth.GetAllowAgentUploadsAsync(user.Id, CancellationToken.None));
        Assert.True(await auth.SetAllowAgentUploadsAsync(user.Id, true, CancellationToken.None));
        Assert.True(await auth.GetAllowAgentUploadsAsync(user.Id, CancellationToken.None));
        Assert.True(await service.SetAccessLevelAsync((await db.ApiTokens.SingleAsync()).Id, user.Id, ApiTokens.AccessLevels.Own, CancellationToken.None));

        var rows = await db.Shares.AsNoTracking().ToDictionaryAsync(x => x.ShareToken);
        Assert.Equal(tokenId, rows["agent-made"].CreatedByApiTokenId);
        Assert.True(rows["agent-made"].SentByAgent);
        Assert.Null(rows["browser-made"].CreatedByApiTokenId);
        Assert.False(rows["browser-made"].SentByAgent);
        var manager = CreateShareManager(db, Path.GetTempPath(), new RecordingJobClient());
        var owner = ShareOwner.For(user.Id, user.Email);
        Assert.Equal(["agent-made"], (await manager.ListSharesForAgentAsync(owner, tokenId, 10, CancellationToken.None)).Select(x => rows.Values.Single(r => r.Id == x.ShareId).ShareToken));
        Assert.Equal(2, (await manager.ListSharesForAgentAsync(owner, null, 10, CancellationToken.None)).Count);
    }

    [SkippableFact]
    public async Task Owner_backfill_stamps_legacy_rows_by_lower_cased_address()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = "uploader@example.com",
            EmailConfirmed = true,
            PasswordHash = "x:y",
            SecurityStamp = SecurityStamps.New(),
            UploadToken = "backfill",
            CreatedAtUtc = DateTime.UtcNow
        };
        var share = NewShare("backfill-share", DateTime.UtcNow);
        share.OwnerUserId = null;
        share.UploaderEmail = "Uploader@Example.com";
        var orphan = NewShare("backfill-orphan", DateTime.UtcNow);
        orphan.OwnerUserId = null;
        orphan.UploaderEmail = "gone@example.com";
        db.Users.Add(user);
        db.Shares.AddRange(share, orphan);
        db.AccountTemplates.Add(new AccountTemplate { Id = Guid.NewGuid(), UploaderEmail = "UPLOADER@example.com", UpdatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var first = await OwnerBackfill.RunAsync(db, CancellationToken.None);
        Assert.Equal(new OwnerBackfill.Result(false, 1, 1, 1, 0), first);
        Assert.Equal(user.Id, (await db.Shares.SingleAsync(x => x.ShareToken == "backfill-share")).OwnerUserId);
        Assert.Null((await db.Shares.SingleAsync(x => x.ShareToken == "backfill-orphan")).OwnerUserId);
        Assert.Equal(user.Id, (await db.AccountTemplates.SingleAsync()).OwnerUserId);

        // Completed once: a later start never assigns rows again, even when they would match an account now.
        var late = NewShare("backfill-late", DateTime.UtcNow);
        late.OwnerUserId = null;
        db.Shares.Add(late);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        Assert.Equal(new OwnerBackfill.Result(true, 0, 0, 2, 0), await OwnerBackfill.RunAsync(db, CancellationToken.None));
        Assert.Null((await db.Shares.SingleAsync(x => x.ShareToken == "backfill-late")).OwnerUserId);
    }

    [SkippableFact]
    public async Task Login_is_case_insensitive_for_email()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        var auth = new AuthService(db, new NoopEmailSender());

        var registered = await auth.RegisterAsync(" Mixed.Case@Example.COM ", "CorrectHorseBatteryStaple!", "https://agora.test/auth/confirm-email", CancellationToken.None);
        Assert.True(registered.Success, registered.Error);

        var user = await db.Users.SingleAsync();
        Assert.Equal("mixed.case@example.com", user.Email);
        user.EmailConfirmed = true;
        await db.SaveChangesAsync();

        var login = await auth.LoginAsync("MIXED.case@example.com", "CorrectHorseBatteryStaple!", "203.0.113.1", CancellationToken.None);
        Assert.True(login.Success, login.Error);
    }

    [SkippableFact]
    public async Task Utc_timestamps_round_trip()
    {
        await using var app = await CreateAppAsync();
        var created = new DateTime(2026, 10, 12, 8, 30, 15, DateTimeKind.Utc);
        var share = NewShare("utc_token", created);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(share);
            await db.SaveChangesAsync();
        }

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var loaded = await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Shares.AsNoTracking().SingleAsync(x => x.Id == share.Id);
            Assert.Equal(created, loaded.CreatedAtUtc);
            Assert.Equal(DateTimeKind.Utc, loaded.CreatedAtUtc.Kind);
            Assert.Equal(created.AddDays(1), loaded.ExpiresAtUtc);
        }

        // Npgsql rejects non-UTC kinds for timestamptz; writes must already be UTC at the source.
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(NewShare("local_token", DateTime.Now));
            await Assert.ThrowsAnyAsync<Exception>(() => db.SaveChangesAsync());
        }
    }

    [SkippableFact]
    public async Task Duplicate_share_token_is_detected_as_token_conflict()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        db.Shares.Add(NewShare("dup_token", DateTime.UtcNow));
        await db.SaveChangesAsync();

        db.Shares.Add(NewShare("dup_token", DateTime.UtcNow));
        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        var pg = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, pg.SqlState);
        Assert.True(ShareManager.IsShareTokenConflict(ex));
    }

    [SkippableFact]
    public async Task Create_share_with_taken_requested_token_reports_token_in_use()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        db.Users.Add(TestUsers.Seed(UploaderId, "uploader@example.com"));
        db.Shares.Add(NewShare("taken_token", DateTime.UtcNow));
        await db.SaveChangesAsync();

        var storageRoot = Path.Combine(Path.GetTempPath(), "agora-pg-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storageRoot);
        try
        {
            var manager = CreateShareManager(db, storageRoot, new RecordingJobClient());
            var filePath = Path.Combine(storageRoot, "upload.txt");
            await File.WriteAllTextAsync(filePath, "hello");

            var ex = await Assert.ThrowsAsync<ShareTokenCollisionException>(() => manager.CreateShareAsync(new CreateShareCommand
            {
                UploaderEmail = "Uploader@Example.com",
                OwnerUserId = UploaderId,
                ShareToken = "taken_token",
                NotifyMode = "none",
                ExpiryMode = ExpiryMode.Date,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1),
                TemplateMode = TemplateMode.AccountDefault,
                Files = [new UploadSourceFile(filePath, "upload.txt", 5, "text/plain")]
            }, CancellationToken.None));
            Assert.Contains("already in use", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(storageRoot, recursive: true);
        }
    }

    [SkippableFact]
    public async Task Notify_once_sets_first_download_once_and_sends_one_notification()
    {
        await using var app = await CreateAppAsync();
        var share = NewShare("once_token", DateTime.UtcNow);
        share.NotifyMode = "once";
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(share);
            await db.SaveChangesAsync();
        }

        var jobs = new RecordingJobClient();
        for (var i = 0; i < 2; i++)
        {
            // Separate scopes mimic two independent download requests.
            await using var scope = app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var loaded = await db.Shares.SingleAsync(x => x.Id == share.Id);
            await CreateShareManager(db, Path.GetTempPath(), jobs)
                .RecordDownloadAsync(loaded, "once_token", "127.0.0.1", "test-agent", CancellationToken.None);
        }

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            Assert.Equal(2, await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id));
            Assert.NotNull((await db.Shares.AsNoTracking().SingleAsync(x => x.Id == share.Id)).FirstDownloadedAtUtc);
        }

        Assert.Equal(1, jobs.Count);
    }

    [SkippableFact]
    public async Task Concurrent_notify_once_downloads_send_exactly_one_notification()
    {
        await using var app = await CreateAppAsync();
        var share = NewShare("concurrent_token", DateTime.UtcNow);
        share.NotifyMode = "once";
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(share);
            await db.SaveChangesAsync();
        }

        const int downloads = 8;
        var jobs = new RecordingJobClient();
        using var start = new ManualResetEventSlim(false);
        var tasks = Enumerable.Range(0, downloads).Select(_ => Task.Run(async () =>
        {
            // Independent scopes/DbContexts, each having loaded the share before any download is recorded.
            await using var scope = app.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            var loaded = await db.Shares.SingleAsync(x => x.Id == share.Id);
            start.Wait();
            await CreateShareManager(db, Path.GetTempPath(), jobs)
                .RecordDownloadAsync(loaded, "concurrent_token", "127.0.0.1", "test-agent", CancellationToken.None);
        })).ToList();
        await Task.Delay(500);
        start.Set();
        await Task.WhenAll(tasks);

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            Assert.Equal(downloads, await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id));
            var firstDownloadedAt = (await db.Shares.AsNoTracking().SingleAsync(x => x.Id == share.Id)).FirstDownloadedAtUtc;
            Assert.NotNull(firstDownloadedAt);
            // Set once, by the single winning download: its event carries the same timestamp.
            Assert.True(await db.DownloadEvents.AnyAsync(x => x.ShareId == share.Id && x.DownloadedAtUtc == firstDownloadedAt));
        }

        Assert.Equal(1, jobs.Count);
    }

    [SkippableFact]
    public async Task Failed_download_event_save_rolls_back_first_download_and_sends_nothing()
    {
        await using var app = await CreateAppAsync();
        var share = NewShare("rollback_token", DateTime.UtcNow);
        share.NotifyMode = "once";
        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            db.Shares.Add(share);
            await db.SaveChangesAsync();
        }

        // The conditional ExecuteUpdateAsync succeeds; the DownloadEvent insert that follows in the same transaction fails.
        var jobs = new RecordingJobClient();
        var options = new DbContextOptionsBuilder<PostgresAgoraDbContext>()
            .UseNpgsql(app.ConnectionString)
            .AddInterceptors(new FailDownloadEventInsertInterceptor())
            .Options;
        await using (var failing = new PostgresAgoraDbContext(options))
        {
            var loaded = await failing.Shares.SingleAsync(x => x.Id == share.Id);
            await Assert.ThrowsAsync<InvalidOperationException>(() => CreateShareManager(failing, Path.GetTempPath(), jobs)
                .RecordDownloadAsync(loaded, "rollback_token", "127.0.0.1", "test-agent", CancellationToken.None));
        }

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
            Assert.Null((await db.Shares.AsNoTracking().SingleAsync(x => x.Id == share.Id)).FirstDownloadedAtUtc);
            Assert.Equal(0, await db.DownloadEvents.CountAsync(x => x.ShareId == share.Id));
        }

        Assert.Equal(0, jobs.Count);
    }

    [SkippableFact]
    public async Task Hangfire_schema_is_created()
    {
        await using var app = await CreateAppAsync();
        var storage = DatabaseSetup.CreatePostgreSqlStorage(app.ConnectionString);
        using (storage.GetConnection())
        {
        }

        await using var connection = new NpgsqlConnection(app.ConnectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'hangfire' AND table_name IN ('job', 'jobqueue', 'server')",
            connection);
        Assert.Equal(3L, await command.ExecuteScalarAsync());
    }

    [SkippableFact]
    public async Task Api_token_lifecycle_translates_on_postgres()
    {
        await using var app = await CreateAppAsync();
        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgoraDbContext>();
        var user = TestUsers.Seed(Guid.NewGuid(), "api.user@example.com");
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var service = new ApiTokenService(db);

        // Two pending rows (TokenHash NULL) and then two active rows (AuthCodeHash NULL) coexist under the unique indexes.
        var tokens = new List<string>();
        foreach (var device in new[] { "Mac A", "Mac B" })
        {
            var code = await service.CreatePendingAsync(user.Id, user.SecurityStamp, ApiTokens.CaptureClientId, device, ApiTokenServiceTests.Challenge, ApiTokenServiceTests.Redirect, CancellationToken.None);
            Assert.NotNull(code);
            tokens.Add(code);
        }

        for (var i = 0; i < tokens.Count; i++)
        {
            var exchanged = await service.ExchangeAsync(tokens[i], ApiTokenServiceTests.Verifier, ApiTokenServiceTests.Redirect, ApiTokens.CaptureClientId, CancellationToken.None);
            Assert.True(exchanged.Success, exchanged.Error);
            Assert.False((await service.ExchangeAsync(tokens[i], ApiTokenServiceTests.Verifier, ApiTokenServiceTests.Redirect, ApiTokens.CaptureClientId, CancellationToken.None)).Success);
            tokens[i] = exchanged.AccessToken!;
        }

        Assert.NotNull(await service.ValidateAsync(tokens[0], CancellationToken.None));
        Assert.Equal(2, (await service.ListForUserAsync(user.Id, CancellationToken.None)).Count);
        var row = await db.ApiTokens.AsNoTracking().FirstAsync(x => x.DeviceName == "Mac A");
        Assert.Equal(DateTimeKind.Utc, row.LastUsedAtUtc!.Value.Kind);

        // Stamp rotation: the token stops working and cleanup's correlated ExecuteUpdate revokes both rows.
        await db.Users.Where(x => x.Id == user.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SecurityStamp, SecurityStamps.New()));
        Assert.Null(await service.ValidateAsync(tokens[1], CancellationToken.None));
        Assert.Equal(0, await service.CleanupAsync(CancellationToken.None));
        Assert.Equal(2, await db.ApiTokens.CountAsync(x => x.RevokedAtUtc != null));
    }

    // ---- helpers ----

    private sealed class TestApp(ServiceProvider services, string connectionString) : IAsyncDisposable
    {
        public ServiceProvider Services { get; } = services;
        public string ConnectionString { get; } = connectionString;

        public ValueTask DisposeAsync() => Services.DisposeAsync();
    }

    private async Task<TestApp> CreateAppAsync()
    {
        // AGORA_REQUIRE_POSTGRES_TESTS=1 (CI/release checks): a missing Docker is a failure, not a skip.
        if (fixture.UnavailableReason is not null && Environment.GetEnvironmentVariable("AGORA_REQUIRE_POSTGRES_TESTS") == "1")
        {
            throw new InvalidOperationException($"AGORA_REQUIRE_POSTGRES_TESTS=1 but {fixture.UnavailableReason}");
        }

        Skip.If(fixture.UnavailableReason is not null, fixture.UnavailableReason);

        var connectionString = fixture.NewDatabaseConnectionString();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAgoraDbContext(DatabaseProvider.Postgres, connectionString);
        var sp = services.BuildServiceProvider();

        await using (var scope = sp.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AgoraDbContext>().Database.MigrateAsync();
        }

        return new TestApp(sp, connectionString);
    }

    private static ShareManager CreateShareManager(AgoraDbContext db, string storageRoot, IBackgroundJobClient jobs)
    {
        var options = Options.Create(new AgoraOptions { StorageRoot = storageRoot });
        var objectStore = new FileSystemObjectStore(storageRoot);
        var scratch = new ScratchSpaceMonitor(options.Value, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
        return new ShareManager(db, options, new ShareContentStore(objectStore), objectStore, jobs, new KeyedAsyncLock(), scratch, NullLogger<ShareManager>.Instance);
    }

    private static readonly Guid UploaderId = Guid.NewGuid();

    private static Share NewShare(string token, DateTime createdAtUtc) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = UploaderId,
        UploaderEmail = EmailAddress.Normalize("uploader@example.com"),
        ShareToken = token,
        ZipDisplayName = "files.zip",
        ZipDiskPath = "zips/2026/10/test.zip",
        ZipSizeBytes = 1,
        NotifyMode = "none",
        ShareExperienceType = "archive",
        AccessMode = "download_only",
        CreatedAtUtc = createdAtUtc,
        ExpiresAtUtc = createdAtUtc.AddDays(1)
    };

    private sealed class FailDownloadEventInsertInterceptor : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<DownloadEvent>().Any(x => x.State == EntityState.Added))
            {
                throw new InvalidOperationException("Injected DownloadEvent insert failure.");
            }

            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    private sealed class RecordingJobClient : IBackgroundJobClient
    {
        private int _count;

        public int Count => _count;

        public string Create(Job job, IState state) => Interlocked.Increment(ref _count).ToString();

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
