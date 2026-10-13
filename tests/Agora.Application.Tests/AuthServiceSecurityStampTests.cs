using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Agora.Application.Tests;

public sealed class AuthServiceSecurityStampTests
{
    private const string Email = "user@example.com";
    private const string Password = "CorrectHorseBatteryStaple!";
    private const string Token = "confirmation-token";

    [Fact]
    public async Task ConfirmPasswordChangeAsync_RotatesStamp()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingPasswordHash = PasswordHasher.Hash("AnotherPassword123!");
        user.PendingPasswordTokenHash = TokenCodec.HashToken(Token);
        user.PendingPasswordTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        await harness.Db.SaveChangesAsync();
        var before = user.SecurityStamp;

        var result = await harness.Service.ConfirmPasswordChangeAsync(Email, Token, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        AssertRotated(before, user.SecurityStamp);
    }

    [Fact]
    public async Task ResetPasswordAsync_RotatesStamp()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        user.PasswordResetTokenHash = TokenCodec.HashToken(Token);
        user.PasswordResetTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        await harness.Db.SaveChangesAsync();
        var before = user.SecurityStamp;

        var result = await harness.Service.ResetPasswordAsync(Email, Token, "AnotherPassword123!", CancellationToken.None);

        Assert.True(result.Success, result.Error);
        AssertRotated(before, user.SecurityStamp);
    }

    [Fact]
    public async Task ConfirmEmailChangeAsync_RotatesStamp()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        user.PendingEmail = "renamed@example.com";
        user.PendingEmailTokenHash = TokenCodec.HashToken(Token);
        user.PendingEmailTokenExpiresAtUtc = DateTime.UtcNow.AddHours(1);
        await harness.Db.SaveChangesAsync();
        var before = user.SecurityStamp;

        var result = await harness.Service.ConfirmEmailChangeAsync(Email, Token, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.Equal("renamed@example.com", user.Email);
        AssertRotated(before, user.SecurityStamp);
    }

    [Fact]
    public async Task UpdateRoleAsync_RotatesStampOnlyWhenRoleChanges()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        var before = user.SecurityStamp;

        Assert.True(await harness.Service.UpdateRoleAsync(user.Id, "admin", CancellationToken.None));
        Assert.Equal("admin", user.Role);
        AssertRotated(before, user.SecurityStamp);

        var afterPromotion = user.SecurityStamp;
        Assert.True(await harness.Service.UpdateRoleAsync(user.Id, "admin", CancellationToken.None));
        Assert.Equal(afterPromotion, user.SecurityStamp);
    }

    [Fact]
    public async Task SetEnabledAsync_RotatesStampOnlyWhenStateChanges()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        var before = user.SecurityStamp;

        Assert.True(await harness.Service.SetEnabledAsync(user.Id, false, CancellationToken.None));
        Assert.False(user.IsEnabled);
        AssertRotated(before, user.SecurityStamp);

        var afterDisable = user.SecurityStamp;
        Assert.True(await harness.Service.SetEnabledAsync(user.Id, false, CancellationToken.None));
        Assert.Equal(afterDisable, user.SecurityStamp);
    }

    [Fact]
    public async Task LoginAsync_MintsStampForLegacyRowAndKeepsExistingStamp()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        user.SecurityStamp = string.Empty;
        await harness.Db.SaveChangesAsync();

        var first = await harness.Service.LoginAsync(Email, Password, CancellationToken.None);
        Assert.True(first.Success, first.Error);
        Assert.False(string.IsNullOrEmpty(user.SecurityStamp));

        var minted = user.SecurityStamp;
        var second = await harness.Service.LoginAsync(Email, Password, CancellationToken.None);
        Assert.True(second.Success, second.Error);
        Assert.Equal(minted, user.SecurityStamp);
    }

    [Fact]
    public async Task SetDisplayNameAsync_DoesNotRotateStamp()
    {
        await using var harness = await TestHarness.CreateAsync();
        var user = await harness.UserAsync();
        var before = user.SecurityStamp;

        var result = await harness.Service.SetDisplayNameAsync(Email, "New Name", CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.Equal(before, user.SecurityStamp);
    }

    private static void AssertRotated(string before, string after)
    {
        Assert.False(string.IsNullOrEmpty(after));
        Assert.NotEqual(before, after);
    }

    private sealed class TestHarness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        public AgoraDbContext Db { get; }
        public AuthService Service { get; }

        private TestHarness(SqliteConnection connection, AgoraDbContext db)
        {
            _connection = connection;
            Db = db;
            Service = new AuthService(db, new NoopEmailSender());
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

        public Task<UserAccount> UserAsync() => Db.Users.SingleAsync(x => x.Email == Email);

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
