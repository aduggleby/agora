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
        var user = await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com");
        user.UploadToken = string.Empty;
        await harness.Db.SaveChangesAsync();

        var token = await service.GetOrCreateUploadTokenAsync("user@example.com", CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(token));
        Assert.Matches("^[A-Za-z0-9]{8}$", token!);
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
        Assert.Matches("^[A-Za-z0-9]{8}$", second!);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public async Task SetUploadTokenAsync_AllowsCustomCode()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var result = await service.SetUploadTokenAsync("user@example.com", "AbC123xY", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("AbC123xY", result.UploadToken);
        Assert.Equal("AbC123xY", (await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com")).UploadToken);
    }

    [Fact]
    public async Task SetUploadTokenAsync_RejectsInvalidFormat()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var result = await service.SetUploadTokenAsync("user@example.com", "invalid-token", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("Upload code must be 2-64 letters or numbers.", result.Error);
    }

    [Fact]
    public async Task SetUploadTokenAsync_RejectsDuplicateCode()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var existing = "AbC123xY";
        harness.Db.Users.Add(new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = "second@example.com",
            EmailConfirmed = true,
            PasswordHash = "hash",
            Role = "user",
            IsEnabled = true,
            UploadToken = existing,
            CreatedAtUtc = DateTime.UtcNow
        });
        await harness.Db.SaveChangesAsync();

        var result = await service.SetUploadTokenAsync("user@example.com", existing, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("That upload code is already in use.", result.Error);
    }

    [Fact]
    public async Task SetDisplayNameAsync_UpdatesName()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var result = await service.SetDisplayNameAsync("user@example.com", "Alex Example", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("Alex Example", result.DisplayName);
        Assert.Equal("Alex Example", (await harness.Db.Users.SingleAsync(x => x.Email == "user@example.com")).DisplayName);
    }

    [Fact]
    public async Task SetDisplayNameAsync_RejectsEmptyName()
    {
        await using var harness = await TestHarness.CreateAsync();
        var service = new AuthService(harness.Db, new NoopEmailSender());

        var result = await service.SetDisplayNameAsync("user@example.com", "   ", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("Name is required.", result.Error);
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
