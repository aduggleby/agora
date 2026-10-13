using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Agora.Application.Tests;

/// <summary>Newly assigned passwords are 8 to 128 characters; a wrong password costs the same for every kind of account.</summary>
public sealed class AuthServicePasswordPolicyTests
{
    [Theory]
    [InlineData(7, false)]
    [InlineData(8, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public async Task RegisterAsync_EnforcesTheLengthBoundaries(int length, bool accepted)
    {
        await using var connection = await OpenDbAsync();
        await using var db = NewContext(connection);
        var service = new AuthService(db, new NoopEmailSender());

        var result = await service.RegisterAsync("new@example.com", new string('p', length), "https://files.example.com/auth/confirm-email", CancellationToken.None);

        Assert.Equal(accepted, result.Success);
        if (!accepted)
        {
            Assert.Equal(PasswordPolicy.LengthError, result.Error);
        }
    }

    [Theory]
    [InlineData(7, false)]
    [InlineData(8, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public async Task ResetPasswordAsync_EnforcesTheLengthBoundaries(int length, bool accepted)
    {
        await using var connection = await OpenDbAsync();
        await using var db = NewContext(connection);
        var sender = new RecordingEmailSender();
        db.Users.Add(Seed("reset@example.com", PasswordHasher.Hash("old-password-1")));
        await db.SaveChangesAsync();
        var service = new AuthService(db, sender);
        await service.RequestPasswordResetAsync("reset@example.com", "https://files.example.com/reset-password", CancellationToken.None);
        var token = System.Web.HttpUtility.ParseQueryString(new Uri(sender.LastActionUrl!).Query)["token"]!;

        var result = await service.ResetPasswordAsync("reset@example.com", token, new string('p', length), CancellationToken.None);

        Assert.Equal(accepted, result.Success);
    }

    [Theory]
    [InlineData(7, false)]
    [InlineData(8, true)]
    [InlineData(128, true)]
    [InlineData(129, false)]
    public async Task RequestPasswordChangeAsync_EnforcesTheLengthBoundaries(int length, bool accepted)
    {
        await using var connection = await OpenDbAsync();
        await using var db = NewContext(connection);
        var user = Seed("change@example.com", PasswordHasher.Hash("old-password-1"));
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var service = new AuthService(db, new NoopEmailSender());

        var result = await service.RequestPasswordChangeAsync(user.Id, "old-password-1", new string('p', length), "https://files.example.com/auth/confirm-password-change", CancellationToken.None);

        Assert.Equal(accepted, result.Success);
        if (!accepted)
        {
            Assert.Equal("New password must be 8-128 characters.", result.Error);
        }
    }

    [Fact]
    public async Task LoginAsync_WrongPasswordCostsTheCurrentIterationsForEveryAccountKind()
    {
        await using var connection = await OpenDbAsync();
        await using var db = NewContext(connection);
        db.Users.Add(Seed("legacy@example.com", PasswordHasherTests.LegacyHash("legacy-password-1")));
        db.Users.Add(Seed("current@example.com", PasswordHasher.Hash("current-password-1")));
        await db.SaveChangesAsync();
        var service = new AuthService(db, new NoopEmailSender());

        var legacy = await ObserveAsync(() => service.LoginAsync("legacy@example.com", "wrong", "203.0.113.9", CancellationToken.None));
        var current = await ObserveAsync(() => service.LoginAsync("current@example.com", "wrong", "203.0.113.9", CancellationToken.None));
        var unknown = await ObserveAsync(() => service.LoginAsync("nobody@example.com", "wrong", "203.0.113.9", CancellationToken.None));

        // Every path spends the current cost at least once; the legacy path additionally spends its own (cheaper) check.
        Assert.Equal([100_000, PasswordHasher.CurrentIterations], legacy);
        Assert.Equal([PasswordHasher.CurrentIterations], current);
        Assert.Equal([PasswordHasher.CurrentIterations], unknown);
        Assert.All(new[] { legacy, current, unknown }, calls => Assert.True(calls.Sum() >= PasswordHasher.CurrentIterations));
    }

    private static async Task<List<int>> ObserveAsync(Func<Task> login)
    {
        var iterations = new List<int>();
        PasswordHasher.VerifyObserver.Value = iterations.Add;
        try
        {
            await login();
        }
        finally
        {
            PasswordHasher.VerifyObserver.Value = null;
        }

        return iterations;
    }

    private static async Task<SqliteConnection> OpenDbAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        return connection;
    }

    private static AgoraDbContext NewContext(SqliteConnection connection)
    {
        var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
        db.Database.EnsureCreated();
        return db;
    }

    private static UserAccount Seed(string email, string passwordHash) => new()
    {
        Id = Guid.NewGuid(),
        Email = email,
        EmailConfirmed = true,
        PasswordHash = passwordHash,
        SecurityStamp = SecurityStamps.New(),
        Role = "user",
        IsEnabled = true,
        UploadToken = Guid.NewGuid().ToString("N")[..12],
        CreatedAtUtc = DateTime.UtcNow
    };

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public string? LastActionUrl { get; private set; }
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
        {
            LastActionUrl = message.ActionUrl;
            return Task.CompletedTask;
        }
    }
}
