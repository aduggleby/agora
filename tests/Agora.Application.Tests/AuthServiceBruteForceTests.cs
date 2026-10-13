using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace Agora.Application.Tests;

/// <summary>
/// Sign-in lockout is per (account, client address): an attacker's failures lock out the attacker's address only,
/// while the owner keeps signing in from elsewhere. The per-account failure counters stay for admin visibility.
/// </summary>
public sealed class AuthServiceBruteForceTests
{
    private const string Email = "user@example.com";
    private const string Password = "CorrectHorseBatteryStaple!";
    private const string AttackerIp = "198.51.100.7";
    private const string OwnerIp = "203.0.113.9";

    [Fact]
    public async Task Five_failures_from_one_address_lock_that_address_out_of_the_account_only()
    {
        await using var harness = await TestHarness.CreateAsync();

        for (var i = 1; i <= LoginLockouts.MaxFailures; i++)
        {
            var failed = await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None);
            Assert.False(failed.Success);
            Assert.Equal(AuthService.LoginFailedError, failed.Error);
        }

        // The attacker's address is refused even with the correct password, and reads like a wrong password.
        var attackerWithPassword = await harness.Service.LoginAsync(Email, Password, AttackerIp, CancellationToken.None);
        Assert.False(attackerWithPassword.Success);
        Assert.Equal(AuthService.LoginFailedError, attackerWithPassword.Error);

        // The owner signs in from another address regardless.
        var owner = await harness.Service.LoginAsync(Email, Password, OwnerIp, CancellationToken.None);
        Assert.True(owner.Success, owner.Error);

        // Counters are per account and informational; the owner's success reset them.
        var user = await harness.Db.Users.SingleAsync(x => x.Email == Email);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockoutEndUtc);
    }

    [Fact]
    public async Task Failures_are_counted_per_account_and_the_lock_expires()
    {
        await using var harness = await TestHarness.CreateAsync();

        for (var i = 1; i <= LoginLockouts.MaxFailures; i++)
        {
            await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None);
        }

        var user = await harness.Db.Users.SingleAsync(x => x.Email == Email);
        Assert.Equal(LoginLockouts.MaxFailures, user.FailedLoginCount);
        Assert.NotNull(user.LastFailedLoginAtUtc);

        harness.Clock.Advance(LoginLockouts.Duration + TimeSpan.FromSeconds(1));
        var afterExpiry = await harness.Service.LoginAsync(Email, Password, AttackerIp, CancellationToken.None);
        Assert.True(afterExpiry.Success, afterExpiry.Error);
    }

    [Fact]
    public async Task Successful_login_resets_the_failed_state()
    {
        await using var harness = await TestHarness.CreateAsync();

        await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None);
        await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None);

        var success = await harness.Service.LoginAsync(Email, Password, AttackerIp, CancellationToken.None);
        Assert.True(success.Success);

        var user = await harness.Db.Users.SingleAsync(x => x.Email == Email);
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LastFailedLoginAtUtc);
        Assert.Null(user.LockoutEndUtc);
    }

    private sealed class TestHarness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AgoraDbContext Db { get; }
        public AuthService Service { get; }
        public TestClock Clock { get; } = new();

        private TestHarness(SqliteConnection connection, AgoraDbContext db)
        {
            _connection = connection;
            Db = db;
            Service = new AuthService(db, new NoopEmailSender(), loginLockouts: new LoginLockouts(new MemoryCache(new MemoryCacheOptions()), Clock));
        }

        public static async Task<TestHarness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<AgoraDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new AgoraDbContext(options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = Email,
                EmailConfirmed = true,
                PasswordHash = PasswordHasher.Hash(Password),
                SecurityStamp = SecurityStamps.New(),
                Role = "user",
                IsEnabled = true,
                UploadToken = "seeduser",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            return new TestHarness(connection, db);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
