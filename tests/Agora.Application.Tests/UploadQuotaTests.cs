using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Agora.Infrastructure.Storage;
using Hangfire;
using Hangfire.Common;
using Hangfire.States;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Agora.Application.Tests;

/// <summary>
/// Covers the upload budgets that bound anonymous staging: per-draft count and bytes, open drafts per upload code and
/// client address, the scratch high-water mark, the per-code daily quota, received-share expiry and the sweep.
/// </summary>
public sealed class UploadQuotaTests
{
    private const string Owner = "owner@example.com";
    private static readonly Guid OwnerId = Guid.NewGuid();

    [Fact]
    public async Task StageUploadAsync_RejectsFileBeyondPerDraftCount()
    {
        await using var harness = await Harness.CreateAsync(o => o.MaxFilesPerShare = 2);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        await harness.StageAsync(draftId, "a.txt", 3);
        var second = await harness.StageAsync(draftId, "b.txt", 3);
        var ex = await Assert.ThrowsAsync<UploadLimitException>(() => harness.StageAsync(draftId, "c.txt", 3));

        Assert.Equal(UploadLimitKind.TooManyFiles, ex.Kind);
        Assert.Equal(400, ex.StatusCode);
        Assert.Contains("Max 2", ex.Message, StringComparison.Ordinal);
        Assert.Equal(2, harness.StagedDirectoryCount());

        // Removing a file frees its slot again.
        Assert.True(await harness.Manager.DeleteStagedUploadAsync(OwnerId, draftId, second.UploadId, CancellationToken.None));
        await harness.StageAsync(draftId, "c.txt", 3);
        Assert.Equal(2, harness.StagedDirectoryCount());
    }

    [Fact]
    public async Task StageUploadAsync_RejectsBytesBeyondPerDraftTotal()
    {
        await using var harness = await Harness.CreateAsync(o => o.MaxTotalUploadBytes = 10);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        await harness.StageAsync(draftId, "a.bin", 6);
        var ex = await Assert.ThrowsAsync<UploadLimitException>(() => harness.StageAsync(draftId, "b.bin", 6));

        Assert.Equal(UploadLimitKind.TooManyBytes, ex.Kind);
        Assert.Equal(413, ex.StatusCode);
        Assert.Equal(1, harness.StagedDirectoryCount());

        // Another draft has its own budget.
        var otherDraft = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        await harness.StageAsync(otherDraft, "c.bin", 6);
    }

    [Fact]
    public async Task StageUploadAsync_ParallelRequestsCannotExceedPerDraftCount()
    {
        await using var harness = await Harness.CreateAsync(o => o.MaxFilesPerShare = 5);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        var attempts = Enumerable.Range(0, 20)
            .Select(async i =>
            {
                try
                {
                    await harness.StageAsync(draftId, $"f{i}.txt", 4);
                    return true;
                }
                catch (UploadLimitException ex) when (ex.Kind == UploadLimitKind.TooManyFiles)
                {
                    return false;
                }
            })
            .ToArray();
        var results = await Task.WhenAll(attempts);

        Assert.Equal(5, results.Count(x => x));
        Assert.Equal(5, harness.StagedDirectoryCount());
        var listed = await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, draftId, CancellationToken.None);
        Assert.Equal(5, listed.Count);
    }

    [Fact]
    public async Task StageUploadAsync_FailedCopyReleasesSlotAndDirectory()
    {
        await using var harness = await Harness.CreateAsync(o => o.MaxFilesPerShare = 1);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(() => harness.Manager.StageUploadAsync(
            OwnerId, draftId, "broken.txt", 5, new ThrowingStream(), CancellationToken.None));

        Assert.Equal(0, harness.StagedDirectoryCount());
        await harness.StageAsync(draftId, "ok.txt", 5);
    }

    [Fact]
    public async Task EnsurePublicUploadDraftAsync_CapsOpenDraftsPerToken()
    {
        await using var harness = await Harness.CreateAsync(o => o.PublicUploads.MaxOpenDraftsPerToken = 2);

        var first = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var ex = await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None));
        Assert.Equal(UploadLimitKind.TooManyOpenDrafts, ex.Kind);
        Assert.Equal(429, ex.StatusCode);

        // An already open draft is only touched, and another code has its own budget.
        Assert.Equal(first, await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, first, "code1", "10.0.0.1", CancellationToken.None));
        await harness.Manager.EnsurePublicUploadDraftAsync(Guid.NewGuid(), NewId(), "code2", "10.0.0.1", CancellationToken.None);
    }

    [Fact]
    public async Task EnsurePublicUploadDraftAsync_CapsOpenDraftsPerClientAddress()
    {
        await using var harness = await Harness.CreateAsync(o => o.PublicUploads.MaxOpenDraftsPerIp = 1);

        await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "203.0.113.7", CancellationToken.None);
        var ex = await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(Guid.NewGuid(), NewId(), "code2", "203.0.113.7", CancellationToken.None));
        Assert.Equal(UploadLimitKind.TooManyOpenDrafts, ex.Kind);

        await harness.Manager.EnsurePublicUploadDraftAsync(Guid.NewGuid(), NewId(), "code2", "203.0.113.8", CancellationToken.None);
        // The address is never stored in clear text in the index.
        var index = Path.Combine(harness.StorageRoot, "uploads", "draft-index");
        Assert.DoesNotContain(Directory.EnumerateDirectories(index, "*", SearchOption.AllDirectories), x => x.Contains("203.0.113", StringComparison.Ordinal));
    }

    [Fact]
    public async Task EnsurePublicUploadDraftAsync_DraftsOlderThanRetentionAndFinishedOnesDoNotCount()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.PublicUploads.MaxOpenDraftsPerToken = 1;
            o.PublicUploads.DraftRetentionHours = 1;
        });

        var stale = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        harness.BackdateDraft(stale, TimeSpan.FromHours(2));
        var finished = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.2", CancellationToken.None);
        await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.3", CancellationToken.None));

        await harness.Manager.DeleteDraftShareAsync(OwnerId, finished, CancellationToken.None);
        await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.3", CancellationToken.None);
    }

    [Fact]
    public void ScratchSpaceMonitor_RejectsWhenFreeSpaceWouldDropBelowFloor()
    {
        var options = new AgoraOptions { StorageRoot = Path.GetTempPath(), Scratch = { MinFreeBytes = 1000 } };
        var monitor = new ScratchSpaceMonitor(options, StorageProvider.S3, _ => 1500, _ => 0, new TestClock());

        monitor.EnsureCanAdmit(500);
        var ex = Assert.Throws<UploadLimitException>(() => monitor.EnsureCanAdmit(501));
        Assert.Equal(UploadLimitKind.InsufficientStorage, ex.Kind);
        Assert.Equal(507, ex.StatusCode);

        // Durable bytes of a FileSystem-store share count against the free-space floor too.
        using var reservation = monitor.Reserve(new ScratchDemand(100, 300));
        Assert.Throws<UploadLimitException>(() => monitor.EnsureCanAdmit(101));
        monitor.EnsureCanAdmit(100);
    }

    [Fact]
    public void ScratchSpaceMonitor_ReservationsCountUntilDisposedAndSurviveCacheRefresh()
    {
        var clock = new TestClock();
        var walks = 0;
        var options = new AgoraOptions { StorageRoot = Path.GetTempPath(), Scratch = { MaxBytes = 100, MinFreeBytes = 0 } };
        var monitor = new ScratchSpaceMonitor(options, StorageProvider.S3, _ => long.MaxValue, _ => { walks++; return 40; }, clock);

        // Preflight reserves nothing: it can be repeated and does not charge the budget.
        monitor.EnsureCanAdmit(60);
        monitor.EnsureCanAdmit(60);

        var first = monitor.Reserve(30); // 40 measured + 30 reserved
        var second = monitor.Reserve(30); // 100
        Assert.Throws<UploadLimitException>(() => monitor.EnsureCanAdmit(1));
        Assert.Throws<UploadLimitException>(() => monitor.Reserve(1));
        Assert.Equal(1, walks);

        // A refresh replaces the measured figure but keeps the outstanding reservations.
        clock.Advance(ScratchSpaceMonitor.CacheDuration);
        Assert.Throws<UploadLimitException>(() => monitor.Reserve(1));
        Assert.Equal(2, walks);

        // Releasing an uncommitted reservation (archive build) gives the space back; a committed one (staged
        // upload) keeps counting as measured scratch until the next walk.
        first.Dispose();
        second.Commit();
        second.Dispose();
        Assert.Equal((0L, 0L), monitor.Reserved);
        monitor.EnsureCanAdmit(30);
        Assert.Throws<UploadLimitException>(() => monitor.EnsureCanAdmit(31));
    }

    [Fact]
    public async Task ScratchSpaceMonitor_ConcurrentReservationsAdmitOnlyWhatFits()
    {
        var options = new AgoraOptions { StorageRoot = Path.GetTempPath(), Scratch = { MaxBytes = 100, MinFreeBytes = 0 } };
        var monitor = new ScratchSpaceMonitor(options, StorageProvider.S3, _ => long.MaxValue, _ => 0, new TestClock());

        var attempts = Enumerable.Range(0, 20).Select(_ => Task.Run(() =>
        {
            try
            {
                return monitor.Reserve(30);
            }
            catch (UploadLimitException)
            {
                return null;
            }
        })).ToArray();
        var reservations = await Task.WhenAll(attempts);

        Assert.Equal(3, reservations.Count(x => x is not null));
        Assert.Equal((90L, 0L), monitor.Reserved);
        foreach (var reservation in reservations)
        {
            reservation?.Dispose();
        }

        Assert.Equal((0L, 0L), monitor.Reserved);
    }

    [Theory]
    [InlineData(StorageProvider.S3, false, 0, 100, 0)]
    [InlineData(StorageProvider.S3, true, 30, 200, 0)]
    [InlineData(StorageProvider.FileSystem, false, 0, 100, 200)]
    [InlineData(StorageProvider.FileSystem, true, 30, 200, 230)]
    public void ScratchSpaceMonitor_ArchiveDemandFollowsStorageProvider(StorageProvider provider, bool password, long background, long scratch, long durable)
    {
        var monitor = new ScratchSpaceMonitor(new AgoraOptions(), provider, _ => long.MaxValue, _ => 0, new TestClock());

        Assert.Equal(new ScratchDemand(scratch, durable), monitor.ArchiveDemand(100, password, background));
        Assert.Equal(new ScratchDemand(0, provider == StorageProvider.FileSystem ? 50 : 0), monitor.DurableDemand(50));
    }

    [Fact]
    public void ScratchSpaceMonitor_ReadsRealVolumeFreeSpace()
    {
        // Through the production constructor: the DriveInfo probe must work for StorageRoot, not fail open.
        var root = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "agora-quota-tests", Guid.NewGuid().ToString("N"))).FullName;
        try
        {
            var full = new ScratchSpaceMonitor(
                Options.Create(new AgoraOptions { StorageRoot = root, Scratch = { MinFreeBytes = long.MaxValue } }),
                StorageProvider.FileSystem,
                NullLogger<ScratchSpaceMonitor>.Instance);
            Assert.Throws<UploadLimitException>(() => full.EnsureCanAdmit(0));

            var relaxed = new ScratchSpaceMonitor(
                Options.Create(new AgoraOptions { StorageRoot = root, Scratch = { MinFreeBytes = 1 } }),
                StorageProvider.FileSystem,
                NullLogger<ScratchSpaceMonitor>.Instance);
            relaxed.EnsureCanAdmit(0);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ScratchSpaceMonitor_UnlimitedByDefaultMaxBytes()
    {
        var options = new AgoraOptions { StorageRoot = Path.GetTempPath(), Scratch = { MaxBytes = 0, MinFreeBytes = 0 } };
        var monitor = new ScratchSpaceMonitor(options, StorageProvider.S3, _ => 0, _ => long.MaxValue / 2, new TestClock());

        monitor.EnsureCanAdmit(long.MaxValue / 4);
    }

    [Fact]
    public async Task StageUploadAsync_And_CreateShareAsync_RejectWhenScratchIsFull()
    {
        await using var harness = await Harness.CreateAsync(
            o => o.Scratch.MinFreeBytes = 1024,
            freeBytes: _ => 512);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        var staged = await Assert.ThrowsAsync<UploadLimitException>(() => harness.StageAsync(draftId, "a.txt", 3));
        Assert.Equal(UploadLimitKind.InsufficientStorage, staged.Kind);
        Assert.Equal(0, harness.StagedDirectoryCount());

        var source = Path.Combine(harness.StorageRoot, "source.txt");
        await File.WriteAllTextAsync(source, "hello");
        var created = await Assert.ThrowsAsync<UploadLimitException>(() => harness.Manager.CreateShareAsync(new CreateShareCommand
        {
            UploaderEmail = Owner,
            OwnerUserId = OwnerId,
            ShareExperienceType = "archive",
            AccessMode = "download_only",
            ExpiryMode = ExpiryMode.Indefinite,
            NotifyMode = "none",
            TemplateMode = TemplateMode.PerUpload,
            Files = [new UploadSourceFile(source, "source.txt", 5, "text/plain")]
        }, CancellationToken.None));
        Assert.Equal(UploadLimitKind.InsufficientStorage, created.Kind);
        Assert.Empty(await harness.Db.Shares.ToListAsync());
    }

    [Fact]
    public async Task CreateReceivedShareAsync_IsAuthoritativeUnderConcurrentSubmissions()
    {
        await using var harness = await Harness.CreateAsync(o => o.PublicUploads.MaxSharesPerCodePerDay = 1);

        var attempts = Enumerable.Range(0, 2)
            .Select(async i =>
            {
                try
                {
                    await harness.Manager.CreateReceivedShareAsync(await harness.ReceivedCommandAsync($"r{i}.txt"), CancellationToken.None);
                    return (UploadLimitKind?)null;
                }
                catch (UploadLimitException ex)
                {
                    return ex.Kind;
                }
            })
            .ToArray();
        var results = await Task.WhenAll(attempts);

        Assert.Single(results, x => x is null);
        Assert.Single(results, x => x == UploadLimitKind.DailyQuotaExceeded);
        Assert.Single(await harness.Db.Shares.ToListAsync());

        // The budget belongs to the owner id: a second submission under another address of the same owner is refused too.
        await using var addressHarness = await Harness.CreateAsync(o => o.PublicUploads.MaxSharesPerCodePerDay = 1);
        await addressHarness.Manager.CreateReceivedShareAsync(await addressHarness.ReceivedCommandAsync("a.txt"), CancellationToken.None);
        var otherAddress = await addressHarness.ReceivedCommandAsync("b.txt");
        var renamed = await Assert.ThrowsAsync<UploadLimitException>(() => addressHarness.Manager.CreateReceivedShareAsync(new CreateShareCommand
        {
            UploaderEmail = "renamed-owner@example.com",
            OwnerUserId = OwnerId,
            SenderName = otherAddress.SenderName,
            SenderEmail = otherAddress.SenderEmail,
            ExpiryMode = otherAddress.ExpiryMode,
            NotifyMode = otherAddress.NotifyMode,
            TemplateMode = otherAddress.TemplateMode,
            Files = otherAddress.Files
        }, CancellationToken.None));
        Assert.Equal(UploadLimitKind.DailyQuotaExceeded, renamed.Kind);

        // Bytes are gated the same way; the owner's own shares never count.
        await using var bytesHarness = await Harness.CreateAsync(o => o.PublicUploads.MaxBytesPerCodePerDay = 8);
        await bytesHarness.Manager.CreateReceivedShareAsync(await bytesHarness.ReceivedCommandAsync("a.txt", "12345"), CancellationToken.None);
        var ex = await Assert.ThrowsAsync<UploadLimitException>(() =>
            bytesHarness.Manager.CreateReceivedShareAsync(bytesHarness.ReceivedCommandAsync("b.txt", "1234").Result, CancellationToken.None));
        Assert.Equal(UploadLimitKind.DailyQuotaExceeded, ex.Kind);
    }

    [Fact]
    public async Task SealedDraft_RefusesStagingAndResubmission_AndFinalizeRemovesEverything()
    {
        await using var harness = await Harness.CreateAsync();
        var draftId = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var submitted = await harness.StageAsync(draftId, "submitted.txt", 4);
        var unsubmitted = await harness.StageAsync(draftId, "unsubmitted.txt", 4);

        Assert.True(await harness.Manager.SealDraftAsync(OwnerId, draftId, CancellationToken.None));
        Assert.False(await harness.Manager.SealDraftAsync(OwnerId, draftId, CancellationToken.None));

        var staged = await Assert.ThrowsAsync<UploadLimitException>(() => harness.StageAsync(draftId, "late.txt", 4));
        Assert.Equal(UploadLimitKind.DraftSealed, staged.Kind);
        Assert.Equal(409, staged.StatusCode);
        var reopened = await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, draftId, "code1", "10.0.0.1", CancellationToken.None));
        Assert.Equal(UploadLimitKind.DraftSealed, reopened.Kind);
        Assert.Equal(2, harness.StagedDirectoryCount());

        // Finalize drops the submitted and the unsubmitted payload, the slot markers and the draft itself.
        await harness.Manager.FinalizeDraftAsync(OwnerId, draftId, CancellationToken.None);
        Assert.Equal(0, harness.StagedDirectoryCount());
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));
        Assert.False(Directory.Exists(submitted.DirectoryPath));
        Assert.False(Directory.Exists(unsubmitted.DirectoryPath));

        // The old id can only come back as a brand-new draft, through admission.
        await using var capped = await Harness.CreateAsync(o => o.PublicUploads.MaxOpenDraftsPerToken = 1);
        var finished = await capped.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        await capped.Manager.SealDraftAsync(OwnerId, finished, CancellationToken.None);
        await capped.Manager.FinalizeDraftAsync(OwnerId, finished, CancellationToken.None);
        await capped.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var refused = await Assert.ThrowsAsync<UploadLimitException>(() =>
            capped.Manager.EnsurePublicUploadDraftAsync(OwnerId, finished, "code1", "10.0.0.1", CancellationToken.None));
        Assert.Equal(UploadLimitKind.TooManyOpenDrafts, refused.Kind);
    }

    [Fact]
    public async Task StageUploadAsync_RefusesDraftsFinalizedOrSealedAfterAdmission_ForEveryPurpose()
    {
        await using var harness = await Harness.CreateAsync();

        // Admitted, then finalized while the body was buffering: the late stage must not recreate anything.
        var finalized = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        await harness.StageAsync(finalized, "early.txt", 3);
        await harness.Manager.SealDraftAsync(OwnerId, finalized, CancellationToken.None);
        await harness.Manager.FinalizeDraftAsync(OwnerId, finalized, CancellationToken.None);
        var late = await Assert.ThrowsAsync<UploadLimitException>(() => harness.StageAsync(finalized, "late.txt", 3));
        Assert.Equal(UploadLimitKind.DraftClosed, late.Kind);
        Assert.Equal(409, late.StatusCode);
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", finalized)));
        Assert.Equal(0, harness.StagedDirectoryCount());

        // Backgrounds take the same lock and the same checks: sealed and foreign drafts are refused.
        var sealedDraft = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        await harness.Manager.SealDraftAsync(OwnerId, sealedDraft, CancellationToken.None);
        var background = await Assert.ThrowsAsync<UploadLimitException>(() => harness.Manager.StageUploadAsync(
            OwnerId, sealedDraft, "bg.png", 3, new MemoryStream("png"u8.ToArray()), CancellationToken.None, ShareManager.UploadPurposeTemplateBackground));
        Assert.Equal(UploadLimitKind.DraftSealed, background.Kind);
        var foreign = await Assert.ThrowsAsync<UploadLimitException>(() => harness.Manager.StageUploadAsync(
            Guid.NewGuid(), sealedDraft, "bg.png", 3, new MemoryStream("png"u8.ToArray()), CancellationToken.None, ShareManager.UploadPurposeTemplateBackground));
        Assert.Equal(UploadLimitKind.DraftClosed, foreign.Kind);
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "staged-template-backgrounds")));
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", sealedDraft)));
    }

    [Fact]
    public async Task Sweep_RemovesStaleDraftAndItsPayloadsTogether_AndNeverTouchesARevivedOne()
    {
        await using var harness = await Harness.CreateAsync(o => o.PublicUploads.DraftRetentionHours = 1);
        var draftId = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        await harness.StageAsync(draftId, "old.txt", 3);
        harness.BackdateDraft(draftId, TimeSpan.FromHours(2));

        // Revived before the sweep reaches it: the touch happens under the draft lock, so the sweep keeps all of it.
        await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, draftId, "code1", "10.0.0.1", CancellationToken.None);
        await harness.StageAsync(draftId, "fresh.txt", 3);
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.Equal(2, (await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, draftId, CancellationToken.None)).Count);

        // Stale again: draft and payloads go in one locked section ...
        harness.BackdateDraft(draftId, TimeSpan.FromHours(2));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));
        Assert.Equal(0, harness.StagedDirectoryCount());

        // ... so a GUID revived afterwards starts clean and keeps what it stages through the next sweep.
        await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, draftId, "code1", "10.0.0.1", CancellationToken.None);
        await harness.StageAsync(draftId, "after.txt", 3);
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.Single(await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, draftId, CancellationToken.None));
    }

    [Fact]
    public async Task SealDraftForSubmissionAsync_UnsealsWhenEnqueueFailsAndAllowsARetry()
    {
        await using var harness = await Harness.CreateAsync();
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        await harness.StageAsync(draftId, "a.txt", 3);

        var failed = await Assert.ThrowsAsync<UploadLimitException>(() => harness.Manager.SealDraftForSubmissionAsync(
            OwnerId, draftId, () => throw new InvalidOperationException("queue down"), CancellationToken.None));
        Assert.Equal(UploadLimitKind.QueueUnavailable, failed.Kind);
        Assert.Equal(503, failed.StatusCode);
        Assert.False(harness.Manager.IsDraftSealed(draftId));
        await harness.StageAsync(draftId, "b.txt", 3); // still open

        var enqueued = 0;
        Assert.True(await harness.Manager.SealDraftForSubmissionAsync(OwnerId, draftId, () => { enqueued++; return Task.CompletedTask; }, CancellationToken.None));
        Assert.Equal(1, enqueued);
        Assert.True(harness.Manager.IsDraftSealed(draftId));
        Assert.False(await harness.Manager.SealDraftForSubmissionAsync(OwnerId, draftId, () => { enqueued++; return Task.CompletedTask; }, CancellationToken.None));
        Assert.Equal(1, enqueued);
    }

    [Fact]
    public async Task Sweep_WaitsForInFlightStageAndKeepsTheTouchedDraft()
    {
        await using var harness = await Harness.CreateAsync(o => o.ZombieUploadRetentionHours = 1);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        harness.BackdateDraft(draftId, TimeSpan.FromHours(2));

        // A stage holds the draft lock while its payload streams in; gate the stream so it is in flight.
        var gate = new GateStream(Encoding.ASCII.GetBytes("payload"));
        var staging = harness.Manager.StageUploadAsync(OwnerId, draftId, "slow.txt", 7, gate, CancellationToken.None);
        await gate.Started.Task;

        var sweep = harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        await Task.Delay(200);
        Assert.False(sweep.IsCompleted);
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));

        gate.Release();
        await staging;
        await sweep;

        // The stage refreshed the draft's activity under the lock, so the sweep re-read it as fresh and kept it.
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));
        Assert.Single(await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, draftId, CancellationToken.None));
    }

    [Fact]
    public async Task EnsurePublicUploadDraftAsync_RevivingAStaleDraftGoesThroughAdmission()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.PublicUploads.MaxOpenDraftsPerToken = 1;
            o.PublicUploads.DraftRetentionHours = 1;
        });

        var stale = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        harness.BackdateDraft(stale, TimeSpan.FromHours(2));
        var fresh = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);

        // The stale draft is not counted, but reviving it needs a free slot, which "fresh" occupies.
        var refused = await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, stale, "code1", "10.0.0.1", CancellationToken.None));
        Assert.Equal(UploadLimitKind.TooManyOpenDrafts, refused.Kind);

        await harness.Manager.DeleteDraftShareAsync(OwnerId, fresh, CancellationToken.None);
        Assert.Equal(stale, await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, stale, "code1", "10.0.0.1", CancellationToken.None));
        // Revived: it counts again.
        await Assert.ThrowsAsync<UploadLimitException>(() =>
            harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None));
    }

    [Fact]
    public async Task Sweep_UsesShorterRetentionForAnonymousDrafts()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.PublicUploads.DraftRetentionHours = 1;
            o.ZombieUploadRetentionHours = 24;
        });

        var anonymous = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var signedIn = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        await harness.StageAsync(anonymous, "a.txt", 3);
        await harness.StageAsync(signedIn, "b.txt", 3);
        harness.BackdateDraft(anonymous, TimeSpan.FromHours(2));
        harness.BackdateDraft(signedIn, TimeSpan.FromHours(2));

        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);

        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", anonymous)));
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", signedIn)));
        Assert.Empty(await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, anonymous, CancellationToken.None));
        Assert.Single(await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, signedIn, CancellationToken.None));
    }

    [Fact]
    public async Task GetReceivedShareUsageAsync_CountsOnlyReceivedSharesOfTheOwnerInTheWindow()
    {
        await using var harness = await Harness.CreateAsync();
        var now = DateTime.UtcNow;
        var deleted = ReceivedShare(Owner, now.AddHours(-23), 50);
        deleted.DeletedAtUtc = now.AddHours(-2);
        var ownShare = ReceivedShare(Owner, now.AddHours(-1), 1000);
        ownShare.SenderName = null;
        ownShare.SenderEmail = null;
        harness.Db.Shares.AddRange(
            ReceivedShare(Owner, now.AddHours(-1), 100, 200),
            deleted,
            ReceivedShare(Owner, now.AddHours(-25), 1000),
            ReceivedShare(Guid.NewGuid(), "someone-else@example.com", now.AddHours(-1), 1000),
            ownShare);
        await harness.Db.SaveChangesAsync();

        var usage = await harness.Manager.GetReceivedShareUsageAsync(ShareOwner.For(OwnerId, "Owner@Example.com"), now.AddHours(-24), CancellationToken.None);

        Assert.Equal(2, usage.Count);
        Assert.Equal(350, usage.Bytes);
        Assert.Equal(new ShareManager.ReceivedShareUsage(0, 0), await harness.Manager.GetReceivedShareUsageAsync(ShareOwner.For(Guid.NewGuid(), "nobody@example.com"), now.AddHours(-24), CancellationToken.None));
    }

    [Theory]
    [InlineData(10, 100, 0, 11, 2000, null)]
    [InlineData(10, 100, 0, 10, 2000, "daily limit of uploads")]
    [InlineData(12, 100, 0, 11, 2000, "daily limit of uploads")]
    [InlineData(10, 1500, 600, 11, 2000, "daily data limit")]
    [InlineData(10, 1500, 500, 11, 2000, null)]
    [InlineData(0, 0, 0, 0, 0, null)]
    public void CheckDailyQuota_AppliesCountAndByteBudgets(int shares, long bytes, long incoming, int maxShares, long maxBytes, string? expectedFragment)
    {
        var options = new AgoraPublicUploadOptions { MaxSharesPerCodePerDay = maxShares, MaxBytesPerCodePerDay = maxBytes };

        var error = PublicUploadPolicy.CheckDailyQuota(shares, bytes, incoming, options);

        if (expectedFragment is null)
        {
            Assert.Null(error);
        }
        else
        {
            Assert.Contains(expectedFragment, error, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("7_days", 7 * 24)]
    [InlineData("1_hour", 1)]
    [InlineData("24_hours", 24)]
    [InlineData("30_days", 30 * 24)]
    [InlineData("", 30 * 24)]
    [InlineData(null, 30 * 24)]
    [InlineData("garbage", 30 * 24)]
    public void ResolveExpiry_FollowsOwnerDefaultAndFallsBackToConfiguredDays(string? ownerMode, int expectedHours)
    {
        var now = new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);

        var expiry = PublicUploadPolicy.ResolveExpiry(ownerMode, 30, now);

        Assert.NotEqual("indefinite", expiry.Mode);
        Assert.Equal(now.AddHours(expectedHours), expiry.ExpiresAtUtc);
    }

    [Fact]
    public void ResolveExpiry_HonoursExplicitIndefiniteAndClampsFallbackToOneDay()
    {
        var now = new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc);

        var indefinite = PublicUploadPolicy.ResolveExpiry("Indefinite", 30, now);
        Assert.Equal("indefinite", indefinite.Mode);
        Assert.Null(indefinite.ExpiresAtUtc);

        var clamped = PublicUploadPolicy.ResolveExpiry("unknown", 0, now);
        Assert.Equal(now.AddDays(1), clamped.ExpiresAtUtc);
    }

    [Fact]
    public async Task CleanupZombieUploadsAsync_SweepsStatusFilesDraftsAndIndexByRetention()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.ZombieUploadRetentionHours = 1;
            o.PublicUploads.DraftRetentionHours = 1;
        });
        var statusRoot = Directory.CreateDirectory(Path.Combine(harness.StorageRoot, "uploads", "share-create-status")).FullName;
        var staleStatus = Path.Combine(statusRoot, "stale.json");
        var freshStatus = Path.Combine(statusRoot, "fresh.json");
        await File.WriteAllTextAsync(staleStatus, "{}");
        await File.WriteAllTextAsync(freshStatus, "{}");
        File.SetLastWriteTimeUtc(staleStatus, DateTime.UtcNow.AddHours(-2));

        var staleDraft = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        harness.BackdateDraft(staleDraft, TimeSpan.FromHours(2));
        var freshDraft = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        await harness.StageAsync(freshDraft, "keep.txt", 3);

        // An upload still streaming in (payload, no metadata yet) must survive a sweep that runs meanwhile.
        var inFlight = Directory.CreateDirectory(Path.Combine(harness.StorageRoot, "uploads", "staged", NewId())).FullName;
        await File.WriteAllTextAsync(Path.Combine(inFlight, "payload.bin"), "partial");

        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);

        Assert.False(File.Exists(staleStatus));
        Assert.True(File.Exists(freshStatus));
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", staleDraft)));
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", freshDraft)));
        Assert.True(Directory.Exists(inFlight));
        Assert.Single(await harness.Manager.ListStagedUploadsForDraftAsync(OwnerId, freshDraft, CancellationToken.None));

        var markers = Directory.EnumerateFiles(Path.Combine(harness.StorageRoot, "uploads", "draft-index"), "*", SearchOption.AllDirectories)
            .Select(Path.GetFileName)
            .ToList();
        Assert.DoesNotContain(staleDraft, markers);
        Assert.Contains(freshDraft, markers);
    }

    [Fact]
    public async Task DeleteStagedUploadAsync_RefusesTraversalIntoAnotherStagingRoot()
    {
        await using var harness = await Harness.CreateAsync();
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var background = await harness.Manager.StageUploadAsync(
            OwnerId, draftId, "bg.png", 3, new MemoryStream("png"u8.ToArray()), CancellationToken.None, ShareManager.UploadPurposeTemplateBackground);
        var backgroundDirectory = Path.Combine(harness.StorageRoot, "uploads", "staged-template-backgrounds", background.UploadId);
        Assert.True(Directory.Exists(backgroundDirectory));

        // The share-file removal route must not reach the template-background root through a relative id.
        Assert.False(await harness.Manager.DeleteStagedUploadAsync(OwnerId, draftId, $"../staged-template-backgrounds/{background.UploadId}", CancellationToken.None));
        Assert.False(await harness.Manager.DeleteStagedUploadAsync(OwnerId, draftId, $"..\\staged-template-backgrounds\\{background.UploadId}", CancellationToken.None));
        // Nor may a background be removed as if it were a share file even with its real id.
        Assert.False(await harness.Manager.DeleteStagedUploadAsync(OwnerId, draftId, background.UploadId, CancellationToken.None));
        Assert.True(Directory.Exists(backgroundDirectory));

        var file = await harness.StageAsync(draftId, "a.txt", 3);
        Assert.True(await harness.Manager.DeleteStagedUploadAsync(OwnerId, Guid.Parse(draftId).ToString("D"), file.UploadId.ToUpperInvariant(), CancellationToken.None));
    }

    [Theory]
    [InlineData("../staged-template-backgrounds/0123456789abcdef0123456789abcdef")]
    [InlineData("..")]
    [InlineData("/tmp")]
    [InlineData("not-a-guid")]
    public async Task ResolveStagedUploadsAsync_RejectsIdsThatAreNotGuids(string uploadId)
    {
        await using var harness = await Harness.CreateAsync();
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.Manager.ResolveStagedUploadsAsync(OwnerId, [uploadId], draftId, CancellationToken.None));
        Assert.Equal("Uploaded file id is invalid.", ex.Message);
    }

    [Fact]
    public async Task DeleteStagedUploadAsync_RefusesOnceTheDraftIsSealed()
    {
        await using var harness = await Harness.CreateAsync();
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var file = await harness.StageAsync(draftId, "a.txt", 3);
        Assert.True(await harness.Manager.SealDraftAsync(OwnerId, draftId, CancellationToken.None));

        Assert.False(await harness.Manager.DeleteStagedUploadAsync(OwnerId, draftId, file.UploadId, CancellationToken.None));
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "staged", file.UploadId)));
    }

    [Fact]
    public async Task Sweep_KeepsASealedDraftAndItsUploadsUntilTheLongerRetention()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.ZombieUploadRetentionHours = 24;
            o.PublicUploads.DraftRetentionHours = 1;
        });
        var draftId = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var file = await harness.StageAsync(draftId, "a.txt", 3);
        var uploadDirectory = Path.Combine(harness.StorageRoot, "uploads", "staged", file.UploadId);
        Assert.True(await harness.Manager.SealDraftAsync(OwnerId, draftId, CancellationToken.None));

        // Idle past the public-draft retention and the upload itself older than the zombie cutoff: a sealed draft
        // (queued or being read by the job) still gets the full retention, and its upload is not aged out alone.
        harness.BackdateDraft(draftId, TimeSpan.FromHours(2));
        harness.BackdateStagedUpload(file.UploadId, TimeSpan.FromHours(30));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.True(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));
        Assert.True(Directory.Exists(uploadDirectory));

        // The job touching the draft resets the clock.
        harness.BackdateDraft(draftId, TimeSpan.FromHours(25));
        await harness.Manager.RenewProcessingLeaseAsync(OwnerId, draftId, CancellationToken.None);
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.True(Directory.Exists(uploadDirectory));

        // Sealed with activity and lease beyond the long retention: swept together with the draft, under its lock.
        harness.BackdateDraft(draftId, TimeSpan.FromHours(25));
        harness.BackdateDraftLease(draftId, TimeSpan.FromHours(25));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.False(Directory.Exists(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId)));
        Assert.False(Directory.Exists(uploadDirectory));
    }

    [Fact]
    public async Task Sweep_KeepsASealedDraftWithAFreshLeaseAtAnyAge()
    {
        await using var harness = await Harness.CreateAsync(o =>
        {
            o.ZombieUploadRetentionHours = 24;
            o.PublicUploads.DraftRetentionHours = 1;
        });
        var draftId = await harness.Manager.EnsurePublicUploadDraftAsync(OwnerId, NewId(), "code1", "10.0.0.1", CancellationToken.None);
        var file = await harness.StageAsync(draftId, "a.txt", 3);
        var uploadDirectory = Path.Combine(harness.StorageRoot, "uploads", "staged", file.UploadId);
        var draftDirectory = Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId);
        Assert.True(await harness.Manager.SealDraftAsync(OwnerId, draftId, CancellationToken.None));

        // Activity and uploads far older than any retention, but the processing lease (set by sealing) is fresh.
        harness.BackdateDraft(draftId, TimeSpan.FromHours(400));
        harness.BackdateStagedUpload(file.UploadId, TimeSpan.FromHours(400));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.True(Directory.Exists(draftDirectory));
        Assert.True(Directory.Exists(uploadDirectory));

        // A stale lease (job never renewed it) lets the sweep take the draft and its uploads.
        harness.BackdateDraftLease(draftId, TimeSpan.FromHours(25));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.False(Directory.Exists(draftDirectory));
        Assert.False(Directory.Exists(uploadDirectory));
    }

    [Fact]
    public async Task Sweep_AgesOutOrphanedUploadsWhoseDraftIsGone()
    {
        await using var harness = await Harness.CreateAsync(o => o.ZombieUploadRetentionHours = 1);
        var draftId = await harness.Manager.EnsureDraftShareAsync(OwnerId, null, CancellationToken.None);
        var file = await harness.StageAsync(draftId, "a.txt", 3);
        var uploadDirectory = Path.Combine(harness.StorageRoot, "uploads", "staged", file.UploadId);
        Directory.Delete(Path.Combine(harness.StorageRoot, "uploads", "drafts", draftId), recursive: true);

        harness.BackdateStagedUpload(file.UploadId, TimeSpan.FromMinutes(30));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.True(Directory.Exists(uploadDirectory));

        harness.BackdateStagedUpload(file.UploadId, TimeSpan.FromHours(2));
        await harness.Manager.CleanupZombieUploadsAsync(CancellationToken.None);
        Assert.False(Directory.Exists(uploadDirectory));
    }

    private static string NewId() => Guid.NewGuid().ToString("N");

    private static Share ReceivedShare(string owner, DateTime createdAtUtc, params long[] fileSizes) => ReceivedShare(OwnerId, owner, createdAtUtc, fileSizes);

    private static Share ReceivedShare(Guid ownerUserId, string owner, DateTime createdAtUtc, params long[] fileSizes) => new()
    {
        Id = Guid.NewGuid(),
        OwnerUserId = ownerUserId,
        UploaderEmail = owner,
        ShareToken = Guid.NewGuid().ToString("N")[..10],
        ZipDisplayName = "files.zip",
        ZipDiskPath = "zips/2026/10/x.zip",
        ZipSizeBytes = fileSizes.Sum(),
        NotifyMode = "none",
        SenderName = "Sender",
        SenderEmail = "sender@example.com",
        CreatedAtUtc = createdAtUtc,
        Files = fileSizes.Select(size => new ShareFile
        {
            Id = Guid.NewGuid(),
            OriginalFilename = "f.bin",
            StoredRelativePath = "shares/x/f.bin",
            RenderType = "binary",
            OriginalSizeBytes = size,
            DetectedContentType = "application/octet-stream"
        }).ToList()
    };

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        public AgoraDbContext Db { get; }
        public ShareManager Manager { get; }
        public string StorageRoot { get; }

        private Harness(SqliteConnection connection, string storageRoot, AgoraDbContext db, ShareManager manager)
        {
            _connection = connection;
            StorageRoot = storageRoot;
            Db = db;
            Manager = manager;
        }

        public static async Task<Harness> CreateAsync(
            Action<AgoraOptions>? configure = null,
            Func<string, long>? freeBytes = null,
            Func<string, long>? scratchBytes = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AgoraDbContext(new DbContextOptionsBuilder<AgoraDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(TestUsers.Seed(OwnerId, Owner));
            await db.SaveChangesAsync();

            var storageRoot = Path.Combine(Path.GetTempPath(), "agora-quota-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storageRoot);
            var options = new AgoraOptions { StorageRoot = storageRoot };
            configure?.Invoke(options);
            var objectStore = new FileSystemObjectStore(storageRoot);
            var scratch = new ScratchSpaceMonitor(options, StorageProvider.FileSystem, freeBytes ?? (_ => long.MaxValue), scratchBytes ?? (_ => 0), TimeProvider.System);
            var manager = new ShareManager(
                db,
                Options.Create(options),
                new ShareContentStore(objectStore),
                objectStore,
                new NoopBackgroundJobClient(),
                new KeyedAsyncLock(),
                scratch,
                NullLogger<ShareManager>.Instance);

            return new Harness(connection, storageRoot, db, manager);
        }

        public Task<ShareManager.StagedUploadFile> StageAsync(string draftId, string fileName, int bytes)
        {
            var stream = new MemoryStream(Encoding.ASCII.GetBytes(new string('x', bytes)));
            return Manager.StageUploadAsync(OwnerId, draftId, fileName, bytes, stream, CancellationToken.None);
        }

        public async Task<CreateShareCommand> ReceivedCommandAsync(string fileName, string content = "hello")
        {
            var source = Path.Combine(StorageRoot, $"{Guid.NewGuid():N}-{fileName}");
            await File.WriteAllTextAsync(source, content);
            return new CreateShareCommand
            {
                UploaderEmail = Owner,
                OwnerUserId = OwnerId,
                SenderName = "Sender",
                SenderEmail = "sender@example.com",
                ShareExperienceType = "archive",
                AccessMode = "download_only",
                ExpiryMode = ExpiryMode.Indefinite,
                NotifyMode = "none",
                TemplateMode = TemplateMode.PerUpload,
                Files = [new UploadSourceFile(source, fileName, content.Length, "text/plain")]
            };
        }

        public int StagedDirectoryCount()
        {
            var root = Path.Combine(StorageRoot, "uploads", "staged");
            return Directory.Exists(root) ? Directory.EnumerateDirectories(root).Count() : 0;
        }

        /// <summary>Rewrites the draft's last-activity timestamp as if nothing touched it for <paramref name="age"/>.</summary>
        public void BackdateDraftLease(string draftId, TimeSpan age)
        {
            var path = Path.Combine(StorageRoot, "uploads", "drafts", draftId, "draft.json");
            var node = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            node["ProcessingLeaseUtc"] = (DateTime.UtcNow - age).ToString("O");
            File.WriteAllText(path, node.ToJsonString());
        }

        public void BackdateStagedUpload(string uploadId, TimeSpan age)
        {
            var metadataPath = Path.Combine(StorageRoot, "uploads", "staged", uploadId, "metadata.json");
            var node = JsonNode.Parse(File.ReadAllText(metadataPath))!.AsObject();
            node["CreatedAtUtc"] = (DateTime.UtcNow - age).ToString("O");
            File.WriteAllText(metadataPath, node.ToJsonString());
        }

        public void BackdateDraft(string draftId, TimeSpan age)
        {
            var path = Path.Combine(StorageRoot, "uploads", "drafts", draftId, "draft.json");
            var node = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
            node["LastActivityUtc"] = (DateTime.UtcNow - age).ToString("O");
            File.WriteAllText(path, node.ToJsonString());
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await _connection.DisposeAsync();
            if (Directory.Exists(StorageRoot))
            {
                Directory.Delete(StorageRoot, recursive: true);
            }
        }
    }

    private sealed class NoopBackgroundJobClient : IBackgroundJobClient
    {
        public string Create(Job job, IState state) => Guid.NewGuid().ToString("N");

        public bool ChangeState(string jobId, IState state, string expectedState) => true;
    }
}
