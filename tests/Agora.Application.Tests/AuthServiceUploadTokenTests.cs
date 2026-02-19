using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Agora.Application.Tests;

public sealed class AuthServiceUploadTokenTests
{
    [Fact]
    public async Task GetOrCreateUploadTokenAsync_CreatesTokenWhenMissing()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var token = await service.GetOrCreateUploadTokenAsync("user@example.com", CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Equal(token, (await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com")).UploadToken);
    }

    [Fact]
    public async Task RegenerateUploadTokenAsync_ChangesToken()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var first = await service.GetOrCreateUploadTokenAsync("user@example.com", CancellationToken.None);
        var second = await service.RegenerateUploadTokenAsync("user@example.com", CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(second));
        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task FindByUploadTokenAsync_ReturnsEnabledUserOnly()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var active = await service.FindByUploadTokenAsync("active-token", CancellationToken.None);
        var disabled = await service.FindByUploadTokenAsync("disabled-token", CancellationToken.None);

        Assert.NotNull(active);
        Assert.Equal("user@example.com", active!.Email);
        Assert.Null(disabled);
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
                PasswordHash = "hash",
                Role = "user",
                IsEnabled = true,
                UploadToken = "active-token",
                CreatedAtUtc = DateTime.UtcNow
            });
            db.Users.Add(new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = "disabled@example.com",
                EmailConfirmed = true,
                PasswordHash = "hash",
                Role = "user",
                IsEnabled = false,
                UploadToken = "disabled-token",
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
