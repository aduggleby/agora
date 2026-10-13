using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Agora.Application.Tests;

/// <summary>
/// A legacy (unprefixed, 100k-iteration) password hash keeps working and is upgraded in place by a successful sign-in.
/// </summary>
public sealed class AuthServicePasswordRehashTests
{
    private const string Email = "legacy@example.com";
    private const string Password = "legacy-password-1";

    [Fact]
    public async Task LoginAsync_UpgradesLegacyHashWithoutRotatingTheSecurityStamp()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var stamp = SecurityStamps.New();
        db.Users.Add(new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = Email,
            EmailConfirmed = true,
            PasswordHash = PasswordHasherTests.LegacyHash(Password),
            SecurityStamp = stamp,
            Role = "user",
            IsEnabled = true,
            UploadToken = "legacyuser1",
            CreatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync();
        var service = new AuthService(db, new NoopEmailSender());

        var wrong = await service.LoginAsync(Email, "not-the-password", "203.0.113.9", CancellationToken.None);
        Assert.False(wrong.Success);
        var user = await db.Users.SingleAsync(x => x.Email == Email);
        Assert.True(PasswordHasher.NeedsRehash(user.PasswordHash));

        var first = await service.LoginAsync(Email, Password, "203.0.113.9", CancellationToken.None);
        Assert.True(first.Success);
        user = await db.Users.SingleAsync(x => x.Email == Email);
        Assert.StartsWith("v2$", user.PasswordHash, StringComparison.Ordinal);
        Assert.False(PasswordHasher.NeedsRehash(user.PasswordHash));
        Assert.True(PasswordHasher.Verify(Password, user.PasswordHash));
        Assert.Equal(stamp, user.SecurityStamp);

        var upgradedHash = user.PasswordHash;
        var second = await service.LoginAsync(Email, Password, "203.0.113.9", CancellationToken.None);
        Assert.True(second.Success);
        Assert.Equal(upgradedHash, (await db.Users.SingleAsync(x => x.Email == Email)).PasswordHash);
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
