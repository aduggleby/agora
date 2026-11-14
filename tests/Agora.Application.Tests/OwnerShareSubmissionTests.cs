using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Agora.Web.Services;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>Validation and payload building of an owner's share submission, shared by the browser and agent callers.</summary>
public sealed class OwnerShareSubmissionTests
{
    private static readonly Guid OwnerId = Guid.NewGuid();
    private static readonly DateTime Now = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("1_hour", 1)]
    [InlineData("24_hours", 24)]
    [InlineData("7_days", 7 * 24)]
    [InlineData("30_days", 30 * 24)]
    public async Task Relative_expiry_modes_count_from_now(string mode, int hours)
    {
        await using var f = await Fixture.CreateAsync();
        var payload = await f.PrepareOkAsync(f.Request() with { ExpiryMode = mode });

        Assert.Equal(mode, payload.ExpiryMode);
        Assert.Equal(Now.AddHours(hours), payload.ExpiresAtUtc);
    }

    [Fact]
    public async Task One_year_and_indefinite_expiry()
    {
        await using var f = await Fixture.CreateAsync();

        var year = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "1_YEAR" });
        Assert.Equal("1_year", year.ExpiryMode);
        Assert.Equal(Now.AddYears(1), year.ExpiresAtUtc);

        var never = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite" });
        Assert.Null(never.ExpiresAtUtc);
    }

    [Fact]
    public async Task Account_default_expiry_and_notify_use_the_owners_settings()
    {
        await using var f = await Fixture.CreateAsync();
        var payload = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "account_default", NotifyMode = "account_default" });

        Assert.Equal("7_days", payload.ExpiryMode);
        Assert.Equal(Now.AddDays(7), payload.ExpiresAtUtc);
        Assert.Equal("once", payload.NotifyMode);

        Assert.True(await f.Auth.SetDefaultExpiryModeAsync(OwnerId, "indefinite", CancellationToken.None));
        Assert.True(await f.Auth.SetDefaultNotifyModeAsync(OwnerId, "every_time", CancellationToken.None));
        var changed = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "account_default", NotifyMode = "account_default" });
        Assert.Equal("indefinite", changed.ExpiryMode);
        Assert.Null(changed.ExpiresAtUtc);
        Assert.Equal("every_time", changed.NotifyMode);
    }

    [Fact]
    public async Task Unknown_expiry_and_notify_modes_are_refused()
    {
        await using var f = await Fixture.CreateAsync();

        var expiry = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "soon" });
        Assert.Equal(400, expiry.Status);
        Assert.StartsWith("expiryMode must be", expiry.Message);

        var blank = await f.PrepareRefusedAsync(f.Request());
        Assert.StartsWith("expiryMode must be", blank.Message);

        var notify = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite", NotifyMode = "always" });
        Assert.Equal("notifyMode must be account_default|none|once|every_time", notify.Message);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("once")]
    [InlineData("every_time")]
    public async Task Notify_modes_pass_through(string mode)
    {
        await using var f = await Fixture.CreateAsync();
        var payload = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite", NotifyMode = mode.ToUpperInvariant() });
        Assert.Equal(mode, payload.NotifyMode);
    }

    [Fact]
    public async Task Browser_date_mode_reads_local_time_and_must_be_in_the_future()
    {
        await using var f = await Fixture.CreateAsync();
        var local = DateTime.SpecifyKind(Now.AddDays(3), DateTimeKind.Local);
        var payload = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "date", ExpiresAtUtc = local.ToString("yyyy-MM-dd HH:mm:ss") });
        Assert.Equal("date", payload.ExpiryMode);
        Assert.Equal(local.ToUniversalTime(), payload.ExpiresAtUtc);

        var past = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "date", ExpiresAtUtc = "2000-01-01 00:00:00" });
        Assert.Equal("expiresAtUtc must be in the future", past.Message);

        var missing = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "date", ExpiresAtUtc = "not a date" });
        Assert.Equal("expiresAtUtc is required for date mode", missing.Message);
    }

    [Theory]
    [InlineData("2026-12-01T10:30:00Z", "2026-12-01T10:30:00")]
    [InlineData("2026-12-01T10:30:00+02:00", "2026-12-01T08:30:00")]
    [InlineData("2026-12-01T10:30:00.250-05:00", "2026-12-01T15:30:00.250")]
    public async Task Absolute_expires_at_with_an_offset_is_converted_to_utc(string value, string expectedUtc)
    {
        await using var f = await Fixture.CreateAsync();
        var payload = await f.PrepareOkAsync(f.Request() with { ExpiresAt = value });

        Assert.Equal("date", payload.ExpiryMode);
        Assert.Equal(DateTime.Parse(expectedUtc, null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal), payload.ExpiresAtUtc);
        Assert.Equal(DateTimeKind.Utc, payload.ExpiresAtUtc!.Value.Kind);
    }

    [Theory]
    [InlineData("2026-12-01T10:30:00")]
    [InlineData("2026-12-01")]
    [InlineData("tomorrow")]
    public async Task Absolute_expires_at_without_an_offset_is_refused(string value)
    {
        await using var f = await Fixture.CreateAsync();
        var refusal = await f.PrepareRefusedAsync(f.Request() with { ExpiresAt = value });
        Assert.StartsWith("expiresAt must be an RFC 3339 timestamp", refusal.Message);
    }

    [Fact]
    public async Task Absolute_expires_at_must_be_in_the_future_and_not_mix_with_a_relative_mode()
    {
        await using var f = await Fixture.CreateAsync();

        var past = await f.PrepareRefusedAsync(f.Request() with { ExpiresAt = "2026-11-14T13:00:00+02:00" });
        Assert.Equal("expiresAt must be in the future", past.Message);

        var mixed = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "7_days", ExpiresAt = "2026-12-01T10:30:00Z" });
        Assert.StartsWith("expiresAt can only be combined", mixed.Message);

        var explicitDate = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "date", ExpiresAt = "2026-12-01T10:30:00Z" });
        Assert.Equal(new DateTime(2026, 12, 1, 10, 30, 0, DateTimeKind.Utc), explicitDate.ExpiresAtUtc);
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("   ", true)]
    [InlineData("1234567", false)]
    [InlineData("12345678", true)]
    [InlineData("  12345678  ", true)]
    public async Task Download_password_needs_at_least_eight_characters_when_given(string password, bool accepted)
    {
        await using var f = await Fixture.CreateAsync();
        var request = f.Request() with { ExpiryMode = "indefinite", DownloadPassword = password };

        if (accepted)
        {
            var payload = await f.PrepareOkAsync(request);
            Assert.Equal(string.IsNullOrWhiteSpace(password) ? null : password.Trim(), payload.DownloadPassword);
        }
        else
        {
            var refusal = await f.PrepareRefusedAsync(request);
            Assert.Equal("downloadPassword must be at least 8 characters when provided", refusal.Message);
        }
    }

    [Fact]
    public async Task Download_password_is_capped_at_256_characters()
    {
        await using var f = await Fixture.CreateAsync();

        var longest = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite", DownloadPassword = new string('a', 256) });
        Assert.Equal(256, longest.DownloadPassword!.Length);

        var tooLong = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite", DownloadPassword = new string('a', 257) });
        Assert.StartsWith("downloadPassword must be", tooLong.Message);
    }

    [Fact]
    public async Task A_custom_share_link_that_is_not_valid_is_refused_as_plain_text()
    {
        await using var f = await Fixture.CreateAsync();
        var refusal = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite", ShareToken = "short" });

        Assert.True(refusal.PlainText);
        Assert.Equal(400, refusal.Status);
        Assert.Equal("Share link must be 8-64 letters, numbers, hyphens, or underscores.", refusal.Message);
    }

    [Fact]
    public async Task A_custom_share_link_is_kept_and_a_blank_one_is_generated()
    {
        await using var f = await Fixture.CreateAsync();

        var custom = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite", ShareToken = "  my-own-link  " });
        Assert.Equal("my-own-link", custom.ShareToken);

        var generated = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite" });
        Assert.Equal(8, generated.ShareToken.Length);
    }

    [Fact]
    public async Task Inline_files_and_a_missing_draft_or_file_are_refused()
    {
        await using var f = await Fixture.CreateAsync();

        Assert.Equal("draftShareId is required", (await f.PrepareRefusedAsync(f.Request() with { DraftShareId = " " })).Message);
        Assert.StartsWith("Please wait for file uploads", (await f.PrepareRefusedAsync(f.Request() with { InlineFileCount = 1 })).Message);

        var empty = await Fixture.CreateAsync();
        await using (empty)
        {
            var draft = await empty.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
            var refusal = await empty.PrepareRefusedAsync(new OwnerShareRequest(draft, UploadedFileIds: [], ExpiryMode: "indefinite"));
            Assert.Equal("At least one file is required", refusal.Message);
        }
    }

    [Fact]
    public async Task File_count_and_size_limits_are_refused()
    {
        await using var f = await Fixture.CreateAsync(fileCount: 3, fileBytes: 10);

        var count = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite" }, new AgoraOptions { MaxFilesPerShare = 2 });
        Assert.Equal("Too many files. Max 2", count.Message);

        var size = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite" }, new AgoraOptions { MaxFileSizeBytes = 9 });
        Assert.Equal("File 'file0.txt' exceeds max size", size.Message);

        var total = await f.PrepareRefusedAsync(f.Request() with { ExpiryMode = "indefinite" }, new AgoraOptions { MaxTotalUploadBytes = 29 });
        Assert.Equal("Total upload size exceeds limit", total.Message);

        var fits = await f.PrepareOkAsync(f.Request() with { ExpiryMode = "indefinite" }, new AgoraOptions { MaxFilesPerShare = 3, MaxFileSizeBytes = 10, MaxTotalUploadBytes = 30 });
        Assert.Equal(3, fits.UploadedFileIds.Count);
    }

    [Fact]
    public async Task The_payload_carries_the_form_fields_and_can_be_adjusted_with_a_with_expression()
    {
        await using var f = await Fixture.CreateAsync();
        var payload = await f.PrepareOkAsync(f.Request() with
        {
            ExpiryMode = "indefinite",
            ShowPreviews = "on",
            Message = "hello",
            ZipFileName = "bundle",
            TemplateMode = "PER_UPLOAD",
            TemplateBackgroundColorHex = "ABCDEF",
            TemplateContainerPosition = "nowhere"
        });

        Assert.Equal("owner@example.com", payload.UploaderEmail);
        Assert.Equal(OwnerId, payload.OwnerUserId);
        Assert.True(payload.ShowPreviews);
        Assert.Equal("hello", payload.Message);
        Assert.Equal("per_upload", payload.TemplateMode);
        Assert.Equal("#abcdef", payload.TemplateBackgroundColorHex);
        Assert.Equal("center", payload.TemplateContainerPosition);
        Assert.Equal("changed", (payload with { Message = "changed" }).Message);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly string _root;
        private readonly AgoraOptions _options;
        private readonly ScratchSpaceMonitor _scratch;
        private readonly ShareCreationStatusStore _status;
        private readonly string _draft;
        private readonly IReadOnlyList<string> _fileIds;

        public ShareManager Manager { get; }
        public AuthService Auth { get; }

        private Fixture(SqliteConnection connection, string root, AgoraOptions options, ShareManager manager, AuthService auth,
            ScratchSpaceMonitor scratch, ShareCreationStatusStore status, string draft, IReadOnlyList<string> fileIds)
        {
            _connection = connection;
            _root = root;
            _options = options;
            Manager = manager;
            Auth = auth;
            _scratch = scratch;
            _status = status;
            _draft = draft;
            _fileIds = fileIds;
        }

        public static async Task<Fixture> CreateAsync(int fileCount = 1, int fileBytes = 3)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(TestUsers.Seed(OwnerId, "owner@example.com"));
            await db.SaveChangesAsync();

            var root = Path.Combine(Path.GetTempPath(), "agora-owner-submission-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var options = new AgoraOptions { StorageRoot = root };
            var wrapped = Options.Create(options);
            var objectStore = new FileSystemObjectStore(root);
            var scratch = new ScratchSpaceMonitor(options, StorageProvider.FileSystem, _ => long.MaxValue, _ => 0, TimeProvider.System);
            var manager = new ShareManager(
                db, wrapped, new ShareContentStore(objectStore), objectStore, new NoopJobClient(), new KeyedAsyncLock(),
                scratch, NullLogger<ShareManager>.Instance);
            var draft = await manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
            var ids = new List<string>();
            for (var i = 0; i < fileCount; i++)
            {
                var staged = await manager.StageUploadAsync(
                    OwnerId, draft, $"file{i}.txt", fileBytes, new MemoryStream(new byte[fileBytes]), CancellationToken.None);
                ids.Add(staged.UploadId);
            }

            return new Fixture(connection, root, options, manager, new AuthService(db, new NoopEmailSender()), scratch,
                new ShareCreationStatusStore(wrapped), draft, ids);
        }

        public OwnerShareRequest Request() => new(_draft, UploadedFileIds: _fileIds, NotifyMode: "none");

        public Task<PreparedShare> PrepareAsync(OwnerShareRequest request, AgoraOptions? cfg = null) =>
            OwnerShareSubmission.PrepareAsync(
                Manager, Auth, _scratch, _status, cfg ?? _options, new ShareOwner(OwnerId, "owner@example.com"), request,
                CancellationToken.None, Now);

        public async Task<QueuedShareCreationJob.Payload> PrepareOkAsync(OwnerShareRequest request, AgoraOptions? cfg = null)
        {
            var prepared = await PrepareAsync(request, cfg);
            Assert.Null(prepared.Refusal);
            return prepared.Payload!;
        }

        public async Task<ShareRefusal> PrepareRefusedAsync(OwnerShareRequest request, AgoraOptions? cfg = null)
        {
            var prepared = await PrepareAsync(request, cfg);
            Assert.Null(prepared.Payload);
            return prepared.Refusal!;
        }

        public async ValueTask DisposeAsync()
        {
            await _connection.DisposeAsync();
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    private sealed class NoopJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");
        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }

    private sealed class NoopEmailSender : IEmailSender
    {
        public Task SendDownloadNotificationAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task SendAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<string> RenderDownloadNotificationHtmlAsync(DownloadNotification notification, CancellationToken cancellationToken) => Task.FromResult(string.Empty);

        public Task<string> RenderAuthEmailHtmlAsync(AuthEmailMessage message, CancellationToken cancellationToken) => Task.FromResult(string.Empty);
    }
}
