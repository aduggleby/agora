using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;

namespace Agora.Application.Tests;

public sealed class ApiTokenServiceTests
{
    internal const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    internal const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    internal const string Redirect = "http://127.0.0.1:50123/callback";
    private const string Client = ApiTokens.CaptureClientId;

    [Fact]
    public async Task Code_exchange_issues_a_token_that_validates_and_stores_only_hashes()
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync("  Alex's\u0000 MacBook ");

        var result = await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None);

        Assert.True(result.Success);
        Assert.True(ApiTokens.IsWellFormedToken(result.AccessToken));
        Assert.Equal(h.User.Email, result.Email);
        var row = await h.RowAsync();
        Assert.Equal(result.TokenId, row.Id);
        Assert.Equal(ApiTokens.Hash(result.AccessToken!), row.TokenHash);
        Assert.Equal(ApiTokens.DisplayPrefix(result.AccessToken!), row.TokenPrefix);
        Assert.Null(row.AuthCodeHash);
        Assert.Equal("Alex's MacBook", row.DeviceName);

        var identity = await h.Service.ValidateAsync(result.AccessToken, CancellationToken.None);
        Assert.NotNull(identity);
        Assert.Equal(h.User.Id, identity.UserId);
        Assert.Equal(row.Id, identity.TokenId);
        Assert.Equal(h.User.Email, identity.Email);
    }

    [Fact]
    public async Task Code_is_single_use()
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync();

        Assert.True((await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None)).Success);
        var second = await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None);

        Assert.False(second.Success);
        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, second.Error);
    }

    [Fact]
    public async Task Code_expires_after_ten_minutes()
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync();
        h.Clock.Advance(TimeSpan.FromMinutes(10));

        var result = await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None);

        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, result.Error);
    }

    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl", Redirect, Client)]
    [InlineData(Verifier, "http://127.0.0.1:50124/callback", Client)]
    [InlineData(Verifier, Redirect, "other-client")]
    public async Task Mismatch_fails_and_burns_the_code(string verifier, string redirect, string client)
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync();

        var wrong = await h.Service.ExchangeAsync(code, verifier, redirect, client, CancellationToken.None);
        var retry = await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None);

        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, wrong.Error);
        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, retry.Error);
        Assert.NotNull((await h.RowAsync()).RevokedAtUtc);
    }

    [Fact]
    public async Task Missing_parameters_are_invalid_request_and_do_not_burn_the_code()
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync();

        Assert.Equal(ApiTokenExchangeResult.InvalidRequest, (await h.Service.ExchangeAsync(code, "", Redirect, Client, CancellationToken.None)).Error);
        Assert.True((await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task Exchange_fails_when_the_stamp_rotated_or_the_user_was_disabled_after_consent()
    {
        await using var h = await Harness.CreateAsync();
        var code = await h.CodeAsync();
        await h.RotateStampAsync();

        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, (await h.Service.ExchangeAsync(code, Verifier, Redirect, Client, CancellationToken.None)).Error);

        var second = await h.CodeAsync();
        await h.DisableAsync();
        Assert.Equal(ApiTokenExchangeResult.InvalidGrant, (await h.Service.ExchangeAsync(second, Verifier, Redirect, Client, CancellationToken.None)).Error);
    }

    [Fact]
    public async Task CreatePending_refuses_a_disabled_user_and_invalid_inputs()
    {
        await using var h = await Harness.CreateAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.CreatePendingAsync(h.User.Id, h.User.SecurityStamp, "other", "d", Challenge, Redirect, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.CreatePendingAsync(h.User.Id, h.User.SecurityStamp, Client, "d", "short", Redirect, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => h.Service.CreatePendingAsync(h.User.Id, h.User.SecurityStamp, Client, "d", Challenge, "http://localhost:5000/callback", CancellationToken.None));

        await h.DisableAsync();
        Assert.Null(await h.Service.CreatePendingAsync(h.User.Id, h.User.SecurityStamp, Client, "d", Challenge, Redirect, CancellationToken.None));
        Assert.Null(await h.Service.CreatePendingAsync(Guid.NewGuid(), h.User.SecurityStamp, Client, "d", Challenge, Redirect, CancellationToken.None));
    }

    [Fact]
    public async Task CreatePending_refuses_a_session_whose_stamp_is_stale()
    {
        await using var h = await Harness.CreateAsync();
        var cookieStamp = h.User.SecurityStamp;
        await h.RotateStampAsync();

        // A cookie minted before the rotation (for example stolen before a password reset) cannot consent.
        Assert.Null(await h.Service.CreatePendingAsync(h.User.Id, cookieStamp, Client, "d", Challenge, Redirect, CancellationToken.None));
        Assert.Null(await h.Service.CreatePendingAsync(h.User.Id, null, Client, "d", Challenge, Redirect, CancellationToken.None));
        Assert.Empty(await h.Db.ApiTokens.AsNoTracking().ToListAsync());

        var current = (await h.Db.Users.AsNoTracking().SingleAsync(x => x.Id == h.User.Id)).SecurityStamp;
        Assert.NotNull(await h.Service.CreatePendingAsync(h.User.Id, current, Client, "d", Challenge, Redirect, CancellationToken.None));
        Assert.Equal(current, (await h.RowAsync()).IssuedSecurityStamp);
    }

    [Fact]
    public async Task List_returns_utc_timestamps()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();
        await h.Service.ValidateAsync(token, CancellationToken.None);

        var app = Assert.Single(await h.Service.ListForUserAsync(h.User.Id, CancellationToken.None));

        Assert.Equal(DateTimeKind.Utc, app.ConnectedAtUtc.Kind);
        Assert.Equal(DateTimeKind.Utc, app.LastUsedAtUtc!.Value.Kind);
        Assert.EndsWith("Z", app.ConnectedAtUtc.ToString("O"));
    }

    [Fact]
    public async Task Security_stamp_rotation_invalidates_the_token()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();

        await h.RotateStampAsync();

        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
        Assert.Empty(await h.Service.ListForUserAsync(h.User.Id, CancellationToken.None));
    }

    [Fact]
    public async Task Disabling_the_user_invalidates_the_token_even_if_the_stamp_is_unchanged()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();

        await h.Db.Users.Where(x => x.Id == h.User.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.IsEnabled, false));

        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task Revoked_token_is_rejected_and_revoke_is_owner_only_and_idempotent()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();
        var id = (await h.RowAsync()).Id;

        Assert.False(await h.Service.RevokeAsync(id, Guid.NewGuid(), CancellationToken.None));
        Assert.NotNull(await h.Service.ValidateAsync(token, CancellationToken.None));

        Assert.True(await h.Service.RevokeAsync(id, h.User.Id, CancellationToken.None));
        Assert.True(await h.Service.RevokeAsync(id, h.User.Id, CancellationToken.None));
        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
        Assert.Empty(await h.Service.ListForUserAsync(h.User.Id, CancellationToken.None));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("not-a-token")]
    public async Task Unknown_or_malformed_tokens_are_rejected(string? token)
    {
        await using var h = await Harness.CreateAsync();
        await h.TokenAsync();

        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task Idle_expiry_is_measured_from_last_use_else_from_exchange()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();

        // Never used: 180 days after the exchange still works, a moment later it does not.
        h.Clock.Advance(TimeSpan.FromDays(180));
        Assert.NotNull(await h.Service.ValidateAsync(token, CancellationToken.None));

        // That use reset the idle clock.
        h.Clock.Advance(TimeSpan.FromDays(180));
        Assert.NotNull(await h.Service.ValidateAsync(token, CancellationToken.None));

        h.Clock.Advance(TimeSpan.FromDays(180) + TimeSpan.FromSeconds(1));
        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task Never_used_token_expires_180_days_after_exchange()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();

        h.Clock.Advance(TimeSpan.FromDays(180) + TimeSpan.FromSeconds(1));

        Assert.Null(await h.Service.ValidateAsync(token, CancellationToken.None));
    }

    [Fact]
    public async Task LastUsed_is_written_at_most_every_15_minutes()
    {
        await using var h = await Harness.CreateAsync();
        var token = await h.TokenAsync();
        var first = h.Clock.GetUtcNow().UtcDateTime;

        await h.Service.ValidateAsync(token, CancellationToken.None);
        Assert.Equal(first, (await h.RowAsync()).LastUsedAtUtc);

        h.Clock.Advance(TimeSpan.FromMinutes(14));
        await h.Service.ValidateAsync(token, CancellationToken.None);
        Assert.Equal(first, (await h.RowAsync()).LastUsedAtUtc);

        h.Clock.Advance(TimeSpan.FromMinutes(1));
        await h.Service.ValidateAsync(token, CancellationToken.None);
        Assert.Equal(first.AddMinutes(15), (await h.RowAsync()).LastUsedAtUtc);
    }

    [Fact]
    public async Task List_returns_active_tokens_only_newest_first()
    {
        await using var h = await Harness.CreateAsync();
        await h.TokenAsync("Old Mac");
        h.Clock.Advance(TimeSpan.FromMinutes(1));
        await h.TokenAsync("New Mac");
        await h.CodeAsync("Pending Mac");

        var list = await h.Service.ListForUserAsync(h.User.Id, CancellationToken.None);

        Assert.Equal(["New Mac", "Old Mac"], list.Select(x => x.DeviceName));
        Assert.All(list, x => Assert.Equal(8, x.TokenPrefix!.Length));
    }

    [Fact]
    public async Task Cleanup_removes_expired_pending_and_old_dead_rows_and_keeps_live_ones()
    {
        await using var h = await Harness.CreateAsync();
        var live = await h.TokenAsync("live");
        var revoked = await h.TokenAsync("revoked");
        await h.Service.RevokeAsync((await h.RowAsync("revoked")).Id, h.User.Id, CancellationToken.None);
        await h.CodeAsync("pending");

        h.Clock.Advance(TimeSpan.FromMinutes(11));
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.Equal(["live", "revoked"], (await h.Db.ApiTokens.AsNoTracking().Select(x => x.DeviceName).ToListAsync()).Order());

        h.Clock.Advance(TimeSpan.FromDays(31));
        await h.Service.ValidateAsync(live, CancellationToken.None);
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.Equal(["live"], await h.Db.ApiTokens.AsNoTracking().Select(x => x.DeviceName).ToListAsync());

        // A stamp rotation revokes at the next run; the row goes 30 days later.
        await h.RotateStampAsync();
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.NotNull((await h.RowAsync("live")).RevokedAtUtc);
        h.Clock.Advance(TimeSpan.FromDays(31));
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.Empty(await h.Db.ApiTokens.AsNoTracking().ToListAsync());
        Assert.Null(await h.Service.ValidateAsync(revoked, CancellationToken.None));
    }

    [Fact]
    public async Task Cleanup_removes_idle_expired_tokens_30_days_after_they_expired()
    {
        await using var h = await Harness.CreateAsync();
        await h.TokenAsync();

        h.Clock.Advance(TimeSpan.FromDays(200));
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.Single(await h.Db.ApiTokens.AsNoTracking().ToListAsync());

        h.Clock.Advance(TimeSpan.FromDays(11));
        await h.Service.CleanupAsync(CancellationToken.None);
        Assert.Empty(await h.Db.ApiTokens.AsNoTracking().ToListAsync());
    }

    [Fact]
    public async Task Deleting_the_user_deletes_their_tokens()
    {
        await using var h = await Harness.CreateAsync();
        await h.TokenAsync();

        await h.Db.Users.Where(x => x.Id == h.User.Id).ExecuteDeleteAsync();

        Assert.Empty(await h.Db.ApiTokens.AsNoTracking().ToListAsync());
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        public AgoraDbContext Db { get; }
        public FakeTimeProvider Clock { get; }
        public ApiTokenService Service { get; }
        public UserAccount User { get; }

        private Harness(SqliteConnection connection, AgoraDbContext db, FakeTimeProvider clock, UserAccount user)
        {
            _connection = connection;
            Db = db;
            Clock = clock;
            User = user;
            Service = new ApiTokenService(db, clock);
        }

        public static async Task<Harness> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:;Foreign Keys=True");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var user = TestUsers.Seed(Guid.NewGuid(), "app.user@example.com");
            db.Users.Add(user);
            await db.SaveChangesAsync();
            db.ChangeTracker.Clear();
            var clock = new FakeTimeProvider(new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero));
            return new Harness(connection, db, clock, user);
        }

        /// <summary>Consent from a session that carries the user's current stamp.</summary>
        public async Task<string> CodeAsync(string deviceName = "Mac")
        {
            var stamp = (await Db.Users.AsNoTracking().SingleAsync(x => x.Id == User.Id)).SecurityStamp;
            return (await Service.CreatePendingAsync(User.Id, stamp, Client, deviceName, Challenge, Redirect, CancellationToken.None))!;
        }

        public async Task<string> TokenAsync(string deviceName = "Mac")
        {
            var result = await Service.ExchangeAsync(await CodeAsync(deviceName), Verifier, Redirect, Client, CancellationToken.None);
            Assert.True(result.Success, result.Error);
            return result.AccessToken!;
        }

        public Task<ApiToken> RowAsync(string? deviceName = null) =>
            Db.ApiTokens.AsNoTracking().SingleAsync(x => deviceName == null || x.DeviceName == deviceName);

        public Task RotateStampAsync()
        {
            var stamp = SecurityStamps.New();
            return Db.Users.Where(x => x.Id == User.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SecurityStamp, stamp));
        }

        public Task DisableAsync() => new AuthService(Db, new NoopEmailSender()).SetEnabledAsync(User.Id, false, CancellationToken.None);

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class NoopEmailSender : Agora.Application.Abstractions.IEmailSender
    {
        public Task SendDownloadNotificationAsync(Agora.Application.Models.DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SendAuthEmailAsync(Agora.Application.Models.AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
