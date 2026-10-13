using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
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

        var login = await auth.LoginAsync("MIXED.case@example.com", "CorrectHorseBatteryStaple!", CancellationToken.None);
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
        db.Shares.Add(NewShare("taken_token", DateTime.UtcNow));
        await db.SaveChangesAsync();

        var storageRoot = Path.Combine(Path.GetTempPath(), "agora-pg-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(storageRoot);
        try
        {
            var manager = CreateShareManager(db, storageRoot, new RecordingJobClient());
            var filePath = Path.Combine(storageRoot, "upload.txt");
            await File.WriteAllTextAsync(filePath, "hello");

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => manager.CreateShareAsync(new CreateShareCommand
            {
                UploaderEmail = "Uploader@Example.com",
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
        return new ShareManager(db, options, new ShareContentStore(options), jobs, NullLogger<ShareManager>.Instance);
    }

    private static Share NewShare(string token, DateTime createdAtUtc) => new()
    {
        Id = Guid.NewGuid(),
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
