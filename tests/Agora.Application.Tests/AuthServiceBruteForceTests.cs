using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Application.Models;
using Agora.Application.Abstractions;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Agora.Application.Tests;

public sealed class AuthServiceBruteForceTests
{
    [Fact]
    public async Task LoginAsync_LocksAccountAfterFiveFailedAttempts()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        for (var i = 1; i <= 4; i++)
        {
            var failed = await service.LoginAsync("user@example.com", "wrong-pass", CancellationToken.None);
            Assert.False(failed.Success);
            Assert.Equal("Invalid credentials.", failed.Error);
        }

        var lockoutAttempt = await service.LoginAsync("user@example.com", "wrong-pass", CancellationToken.None);
        Assert.False(lockoutAttempt.Success);
        Assert.Equal("Too many failed login attempts. Try again later.", lockoutAttempt.Error);

        var whileLocked = await service.LoginAsync("user@example.com", "CorrectHorseBatteryStaple!", CancellationToken.None);
        Assert.False(whileLocked.Success);
        Assert.Equal("Too many failed login attempts. Try again later.", whileLocked.Error);

        var user = await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com");
        Assert.True(user.FailedLoginCount >= 5);
        Assert.NotNull(user.LockoutEndUtc);
        Assert.True(user.LockoutEndUtc > DateTime.UtcNow);
    }

    [Fact]
    public async Task LoginAsync_ResetsFailedStateAfterSuccessfulLogin()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        await service.LoginAsync("user@example.com", "wrong-pass", CancellationToken.None);
        await service.LoginAsync("user@example.com", "wrong-pass", CancellationToken.None);

        var success = await service.LoginAsync("user@example.com", "CorrectHorseBatteryStaple!", CancellationToken.None);
        Assert.True(success.Success);

        var user = await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com");
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LastFailedLoginAtUtc);
        Assert.Null(user.LockoutEndUtc);
    }

    private sealed class TestHarness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AgoraDbContext Db { get; }

        private TestHarness(SqliteConnection connection, AgoraDbContext db)
        {
            _connection = connection;
            Db = db;
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
                Email = "user@example.com",
                EmailConfirmed = true,
                PasswordHash = PasswordHasher.Hash("CorrectHorseBatteryStaple!"),
                Role = "user",
                IsEnabled = true,
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

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
