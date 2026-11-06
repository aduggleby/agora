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

    [Fact]
    public async Task Unconfirmed_accounts_lock_out_like_confirmed_ones()
    {
        await using var harness = await TestHarness.CreateAsync();
        await harness.MakeUnconfirmedAsync();

        for (var i = 1; i <= LoginLockouts.MaxFailures; i++)
        {
            Assert.Equal(AuthService.LoginFailedError, (await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None)).Error);
        }

        // Locked: the correct password no longer reveals "confirm your email" to this address.
        var locked = await harness.Service.LoginAsync(Email, Password, AttackerIp, CancellationToken.None);
        Assert.False(locked.Success);
        Assert.Equal(AuthService.LoginFailedError, locked.Error);

        var user = await harness.Db.Users.SingleAsync(x => x.Email == Email);
        Assert.Equal(LoginLockouts.MaxFailures, user.FailedLoginCount);

        // Another address with the correct password still learns that the account needs confirming.
        var owner = await harness.Service.LoginAsync(Email, Password, OwnerIp, CancellationToken.None);
        Assert.Equal(AuthService.EmailConfirmationRequiredError, owner.Error);
    }

    [Fact]
    public async Task Wrong_passwords_on_the_confirmation_page_count_toward_the_same_lockout()
    {
        await using var harness = await TestHarness.CreateAsync();
        var token = await harness.MakeUnconfirmedAsync();

        for (var i = 1; i <= LoginLockouts.MaxFailures - 1; i++)
        {
            var wrong = await harness.Service.ConfirmEmailAsync(Email, token, "wrong-pass", AttackerIp, CancellationToken.None);
            Assert.Equal((false, AuthService.ConfirmationPasswordError), wrong);
        }

        // The fifth failure comes from sign-in: both paths share one (account, address) bucket.
        await harness.Service.LoginAsync(Email, "wrong-pass", AttackerIp, CancellationToken.None);

        var locked = await harness.Service.ConfirmEmailAsync(Email, token, Password, AttackerIp, CancellationToken.None);
        Assert.Equal((false, AuthService.ConfirmationPasswordError), locked);
        var user = await harness.Db.Users.SingleAsync(x => x.Email == Email);
        Assert.False(user.EmailConfirmed);
        Assert.NotNull(user.EmailConfirmationTokenHash);

        // The token survived every failure; from another address the right password confirms.
        var confirmed = await harness.Service.ConfirmEmailAsync(Email, token, Password, OwnerIp, CancellationToken.None);
        Assert.True(confirmed.Success, confirmed.Error);
        Assert.True((await harness.Db.Users.SingleAsync(x => x.Email == Email)).EmailConfirmed);
    }

    [Fact]
    public async Task IPv6_addresses_in_one_64_share_a_lockout()
    {
        await using var harness = await TestHarness.CreateAsync();

        for (var i = 1; i <= LoginLockouts.MaxFailures; i++)
        {
            await harness.Service.LoginAsync(Email, "wrong-pass", $"2001:db8:1:2::{i:x}", CancellationToken.None);
        }

        var samePrefix = await harness.Service.LoginAsync(Email, Password, "2001:db8:1:2:ffff:ffff:ffff:ffff", CancellationToken.None);
        Assert.Equal(AuthService.LoginFailedError, samePrefix.Error);

        var otherPrefix = await harness.Service.LoginAsync(Email, Password, "2001:db8:1:3::1", CancellationToken.None);
        Assert.True(otherPrefix.Success, otherPrefix.Error);
    }

    private sealed class TestHarness : IAsyncDisposable
    {
        /// <summary>Turns the seeded account into an unconfirmed one with a live confirmation token, and returns it.</summary>
        public async Task<string> MakeUnconfirmedAsync()
        {
            const string token = "confirmation-token-for-tests";
            var user = await Db.Users.SingleAsync(x => x.Email == Email);
            user.EmailConfirmed = false;
            user.EmailConfirmationTokenHash = TokenCodec.HashToken(token);
            user.EmailConfirmationTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
            await Db.SaveChangesAsync();
            return token;
        }

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
