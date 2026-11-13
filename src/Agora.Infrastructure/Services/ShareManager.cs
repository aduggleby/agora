using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Hangfire;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Agora.Infrastructure.Services;

/// <summary>
/// Orchestrates share lifecycle operations: staging files, creating share archives, resolving templates, and cleanup.
/// </summary>
public sealed partial class ShareManager(
    AgoraDbContext db,
    IOptions<AgoraOptions> options,
    IShareContentStore contentStore,
    IObjectStore objectStore,
    IBackgroundJobClient backgroundJobs,
    KeyedAsyncLock draftLocks,
    ScratchSpaceMonitor scratchSpace,
    ILogger<ShareManager> logger)
{
    public const string UploadPurposeShareFile = "share_file";
    public const string UploadPurposeTemplateBackground = "template_background";

    public sealed record ShareArchiveFileSummary(
        string OriginalFilename,
        long OriginalSizeBytes);

    public sealed record UserShareSummary(
        Guid ShareId,
        string ZipDisplayName,
        long ZipSizeBytes,
        int FileCount,
        int DownloadCount,
        DateTime CreatedAtUtc,
        DateTime? ExpiresAtUtc,
        DateTime? DeletedAtUtc,
        string? SenderName,
        string? SenderEmail,
        string? SenderMessage,
        string AccessMode,
        IReadOnlyList<ShareArchiveFileSummary> Files)
    {
        public bool IsDirectLink => ShareModes.IsDirectLink(AccessMode);
    }

    public sealed record DraftTemplateState(
        string DraftShareId,
        string TemplateMode,
        string Title,
        string H1,
        string Description,
        string? BackgroundImageUrl,
        string? BackgroundUploadId,
        string? BackgroundColorHex,
        string ContainerPosition);

    public sealed record StagedUploadFile(
        string UploadId,
        string OriginalFileName,
        long OriginalSizeBytes,
        string ContentType,
        string TempPath,
        string DirectoryPath);

    private sealed record StagedUploadMetadata(
        string UploadId,
        Guid? OwnerUserId,
        string DraftShareId,
        string OriginalFileName,
        long OriginalSizeBytes,
        string ContentType,
        DateTime CreatedAtUtc,
        string? UploadPurpose);

    private sealed record DraftShareMetadata(
        string DraftShareId,
        Guid? OwnerUserId,
        DateTime LastActivityUtc,
        string TemplateMode,
        string Title,
        string H1,
        string Description,
        string? BackgroundImageUrl,
        string? BackgroundUploadId,
        string? BackgroundColorHex,
        string? ContainerPosition,
        bool PublicUpload = false,
        DateTime? ProcessingLeaseUtc = null);

    private readonly AgoraOptions _options = options.Value;

    public sealed record ShareTokenDiagnostics(
        string Token,
        bool Exists,
        int CaseSensitiveMatchCount,
        int CaseInsensitiveMatchCount,
        Guid? ExistingShareId,
        string? ExistingShareUploader,
        DateTime? ExistingShareCreatedAtUtc,
        string DatabaseProvider);

    public async Task<CreateShareResult> CreateShareAsync(CreateShareCommand command, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var owner = OwnerOf(command);
        var requestedToken = command.ShareToken?.Trim();
        var hasRequestedToken = !string.IsNullOrWhiteSpace(requestedToken);
        var shareExperienceType = ShareModes.ToStorageValue(ShareModes.ParseExperienceType(command.ShareExperienceType));
        var accessMode = ShareModes.ToStorageValue(ShareModes.ParseAccessMode(command.AccessMode));

        var uploadFileNames = command.Files.Select(x => x.OriginalFileName).ToArray();
        var zipName = ArchiveNameResolver.Resolve(command.ZipFileName, uploadFileNames, now);
        var downloadPassword = string.IsNullOrWhiteSpace(command.DownloadPassword)
            ? null
            : command.DownloadPassword;
        // The archive (and its encrypted copy) is built in scratch, and with the FileSystem store the originals and
        // the archive land on the same volume: hold that demand against the budget for the whole build.
        using var scratchReservation = scratchSpace.Reserve(scratchSpace.ArchiveDemand(
            command.Files.Sum(x => Math.Max(0, x.OriginalSizeBytes)),
            downloadPassword is not null,
            command.TemplateMode == TemplateMode.PerUpload ? command.TemplateBackgroundFile?.OriginalSizeBytes ?? 0 : 0));
        // Every durable object written below is tracked so a failure at any step (including the DB save and
        // cancellation) removes it again; scratch files are always deleted.
        string? shareContentRelativePath = null;
        var uploadedKeys = new List<string>();
        var attemptedShareIds = new List<Guid>();
        var scratchZipPath = ScratchFiles.NewPath(_options.StorageRoot, ".zip");
        var scratchEncryptedPath = ScratchFiles.NewPath(_options.StorageRoot, ".agz");
        try
        {
            var persistedContent = await contentStore.PersistShareFilesAsync(command.Files, now, cancellationToken);
            shareContentRelativePath = persistedContent.ContentRootPath;
            var storedFiles = persistedContent.Files;

            await using (var outStream = File.Create(scratchZipPath))
            await using (var zip = new ZipArchive(outStream, ZipArchiveMode.Create))
            {
                foreach (var file in storedFiles)
                {
                    var entry = zip.CreateEntry(file.EntryName, CompressionLevel.Fastest);
                    await using var entryStream = entry.Open();
                    await using var source = File.OpenRead(file.LocalSourcePath);
                    await source.CopyToAsync(entryStream, cancellationToken);
                }
            }

            var zipRelativePath = $"zips/{now:yyyy}/{now:MM}/{Guid.NewGuid()}.zip";
            var archiveDiskPath = zipRelativePath;
            var archiveLocalPath = scratchZipPath;
            if (downloadPassword is not null)
            {
                await ZipEncryption.EncryptFileAsync(scratchZipPath, scratchEncryptedPath, downloadPassword, cancellationToken);
                archiveDiskPath = $"zips/{now:yyyy}/{now:MM}/{Guid.NewGuid()}.agz";
                archiveLocalPath = scratchEncryptedPath;
            }

            var archiveSizeBytes = new FileInfo(archiveLocalPath).Length;
            uploadedKeys.Add(archiveDiskPath);
            await objectStore.PutFileAsync(
                archiveDiskPath,
                archiveLocalPath,
                downloadPassword is null ? "application/zip" : "application/octet-stream",
                cancellationToken);

            // Owner lock from here to the insert: serialized with account deletion (the owner must still exist, and be
            // enabled, when the row is inserted, otherwise the uploaded objects are removed again by the failure path
            // below) and with account background replacement, which deletes the old object only under this lock, so
            // a background read from the template here is still there when it is copied.
            using var ownerLock = await draftLocks.LockAsync(OwnerLockKey(owner.UserId), cancellationToken);
            var template = await ResolveTemplateAsync(command, cancellationToken);
            logger.LogInformation(
                "Resolved download page template for uploader {UploaderEmail} mode {TemplateMode} with background marker {BackgroundMarker}",
                command.UploaderEmail,
                command.TemplateMode,
                template.BackgroundImageUrl ?? "<none>");

            if (command.TemplateMode == TemplateMode.PerUpload && command.TemplateBackgroundFile is not null)
            {
                var backgroundKey = ShareBackgroundKey(zipRelativePath, command.TemplateBackgroundFile.OriginalFileName);
                uploadedKeys.Add(backgroundKey);
                await objectStore.PutFileAsync(backgroundKey, command.TemplateBackgroundFile.TempPath, command.TemplateBackgroundFile.ContentType, cancellationToken);
                var backgroundMarker = $"internal:{backgroundKey}";
                template = template with { BackgroundImageUrl = backgroundMarker };
                logger.LogInformation(
                    "Copied per-share custom background for uploader {UploaderEmail} to marker {BackgroundMarker}",
                    command.UploaderEmail,
                    backgroundMarker);
            }
            else if (command.TemplateMode == TemplateMode.AccountDefault &&
                     !string.IsNullOrWhiteSpace(template.BackgroundImageUrl) &&
                     template.BackgroundImageUrl.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
            {
                var sourceMarker = template.BackgroundImageUrl;
                var copiedMarker = await CopyInternalBackgroundToShareDirectoryAsync(template.BackgroundImageUrl, zipRelativePath, uploadedKeys, cancellationToken);
                template = template with { BackgroundImageUrl = copiedMarker };
                logger.LogInformation(
                    "Copied account default background for uploader {UploaderEmail} from {SourceMarker} to {CopiedMarker}",
                    command.UploaderEmail,
                    sourceMarker ?? "<none>",
                    copiedMarker ?? "<none>");
            }

            if (!await db.Users.AnyAsync(x => x.Id == owner.UserId && x.IsEnabled, cancellationToken))
            {
                throw new InvalidOperationException("The account that owns this share no longer exists.");
            }

            for (var attempt = 0; attempt < 16; attempt += 1)
            {
                var token = hasRequestedToken
                    ? requestedToken!
                    : TokenCodec.GenerateAlphanumericToken(8);

                var share = new Share
                {
                    Id = Guid.NewGuid(),
                    OwnerUserId = owner.UserId,
                    UploaderEmail = owner.Email,
                    ShareToken = token,
                    ZipDisplayName = zipName,
                    ZipDiskPath = archiveDiskPath,
                    ZipSizeBytes = archiveSizeBytes,
                    ShareExperienceType = shareExperienceType,
                    AccessMode = accessMode,
                    ContentRootPath = shareContentRelativePath,
                    DownloadPasswordHash = downloadPassword is null ? null : PasswordHasher.Hash(downloadPassword),
                    UploaderMessage = command.Message,
                    SenderName = command.SenderName,
                    SenderEmail = EmailAddress.NormalizeOptional(command.SenderEmail),
                    SenderMessage = command.SenderMessage,
                    NotifyMode = command.NotifyMode,
                    ExpiresAtUtc = command.ExpiryMode == ExpiryMode.Indefinite ? null : command.ExpiresAtUtc,
                    CreatedAtUtc = now,
                    PageTitle = template.Title,
                    PageH1 = template.H1,
                    PageDescription = template.Description,
                    BackgroundImageUrl = template.BackgroundImageUrl,
                    PageBackgroundColorHex = template.BackgroundColorHex,
                    PageContainerPosition = NormalizeContainerPosition(template.ContainerPosition),
                    Files = storedFiles.Select(x => new ShareFile
                    {
                        Id = Guid.NewGuid(),
                        OriginalFilename = x.EntryName,
                        StoredRelativePath = x.StoredRelativePath,
                        RenderType = DetectRenderType(x.EntryName),
                        OriginalSizeBytes = x.SizeBytes,
                        DetectedContentType = ContentTypePolicy.FromFileName(x.EntryName)
                    }).ToList()
                };

                db.Shares.Add(share);
                attemptedShareIds.Add(share.Id);
                try
                {
                    // The commit is the point of no return: never let a shutdown cancel it halfway, or the job could
                    // be requeued for a share that was in fact created and the re-run would create a second one.
                    await db.SaveChangesAsync(CancellationToken.None);
                    if (hasRequestedToken)
                    {
                        await TryReleaseCommittedClaimAsync(token, owner.UserId);
                    }

                    return new CreateShareResult(share.Id, token, share.ZipDisplayName, share.ExpiresAtUtc);
                }
                catch (DbUpdateException ex) when (IsShareTokenConflict(ex))
                {
                    // The database error text quotes the duplicate key (the token), so neither it nor the exception is
                    // logged or rethrown: only the constraint name travels on.
                    var constraintName = ShareTokenConflictConstraint(ex);
                    logger.LogWarning(
                        "Share token conflict while creating share. share={TokenRef} uploader={Uploader} requestedToken={RequestedTokenRef} hasRequestedToken={HasRequestedToken} provider={Provider} constraint={Constraint}",
                        LogSafe.Token(token),
                        command.UploaderEmail,
                        hasRequestedToken ? LogSafe.Token(requestedToken) : "<none>",
                        hasRequestedToken,
                        db.Database.ProviderName ?? "<unknown>",
                        constraintName);
                    db.Entry(share).State = EntityState.Detached;
                    if (hasRequestedToken)
                    {
                        throw new ShareTokenCollisionException(constraintName);
                    }

                    // Random collision on generated token; retry with a new token.
                }
                catch
                {
                    db.Entry(share).State = EntityState.Detached;
                    throw;
                }
            }

            throw new InvalidOperationException("Unable to generate a unique share token right now.");
        }
        catch
        {
            if (await IsAnyShareCommittedAsync(attemptedShareIds))
            {
                logger.LogWarning(
                    "Share creation failed but a share row may have been committed (ids {ShareIds}); keeping its objects (content root {ContentRoot}, keys {Keys}) for reconciliation",
                    attemptedShareIds,
                    shareContentRelativePath,
                    uploadedKeys);
            }
            else
            {
                await DeleteUploadedObjectsAsync(shareContentRelativePath, uploadedKeys);
            }

            throw;
        }
        finally
        {
            ScratchFiles.TryDelete(scratchZipPath);
            ScratchFiles.TryDelete(scratchEncryptedPath);
        }
    }

    /// <summary>
    /// A save can commit even though it reports a failure (lost acknowledgement), so compensation first checks with a
    /// fresh context whether any attempted share row exists. True when one exists or the check itself fails.
    /// </summary>
    /// <summary>
    /// Creates a share received through the owner's upload link. The owner's daily quota is re-checked against the
    /// committed shares under a per-owner lock that is held until this share is committed too, so the endpoint's
    /// fast-path check cannot be raced by submissions that were admitted before an earlier job finished.
    /// </summary>
    public async Task<CreateShareResult> CreateReceivedShareAsync(CreateShareCommand command, CancellationToken cancellationToken)
    {
        var owner = OwnerOf(command);
        var incomingBytes = command.Files.Sum(x => Math.Max(0, x.OriginalSizeBytes));
        // Keyed on the immutable owner id, so submissions through the same link under different addresses share one
        // budget; every database access happens under the lock.
        using (await draftLocks.LockAsync($"received-quota:{owner.UserId:N}", cancellationToken))
        {
            var usage = await GetReceivedShareUsageAsync(owner, DateTime.UtcNow.AddHours(-24), cancellationToken);
            var error = PublicUploadPolicy.CheckDailyQuota(usage.Count, usage.Bytes, incomingBytes, _options.PublicUploads);
            if (error is not null)
            {
                throw new UploadLimitException(UploadLimitKind.DailyQuotaExceeded, error);
            }

            return await CreateShareAsync(command, cancellationToken);
        }
    }

    /// <summary>
    /// Creates a temporary direct link: the one file staged into the draft is persisted under the usual content root
    /// and served as raw bytes at <c>/s/{token}</c>; no archive is built and no notification is ever sent. Refuses
    /// drafts that hold anything but exactly that one file and files the content policy would not serve inline.
    /// </summary>
    public async Task<CreateShareResult> CreateDirectLinkShareAsync(CreateDirectLinkCommand command, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var owner = ShareOwner.For(command.OwnerUserId, command.UploaderEmail);
        if (!TryNormalizeDraftShareId(command.DraftShareId, out var draftShareId))
        {
            throw new InvalidOperationException("draftShareId is invalid.");
        }

        var staged = await ResolveDirectLinkUploadAsync(owner.UserId, draftShareId, command.UploadId, cancellationToken);
        var file = new UploadSourceFile(staged.TempPath, staged.OriginalFileName, staged.OriginalSizeBytes, staged.ContentType);
        var expiresAtUtc = now.Add(DirectLinkDurations.ToTimeSpan(command.Duration));

        // No archive: only the stored original lands on the durable volume (FileSystem store) or nowhere local (S3).
        using var scratchReservation = scratchSpace.Reserve(scratchSpace.DurableDemand(Math.Max(0, file.OriginalSizeBytes)));
        string? shareContentRelativePath = null;
        var attemptedShareIds = new List<Guid>();
        try
        {
            var persistedContent = await contentStore.PersistShareFilesAsync([file], now, cancellationToken);
            shareContentRelativePath = persistedContent.ContentRootPath;
            var stored = persistedContent.Files.Single();

            // Serialized with account deletion, like CreateShareAsync: the owner must still exist and be enabled.
            using var ownerLock = await draftLocks.LockAsync(OwnerLockKey(owner.UserId), cancellationToken);
            if (!await db.Users.AnyAsync(x => x.Id == owner.UserId && x.IsEnabled, cancellationToken))
            {
                throw new InvalidOperationException("The account that owns this share no longer exists.");
            }

            for (var attempt = 0; attempt < 16; attempt += 1)
            {
                var token = TokenCodec.GenerateAlphanumericToken(8);
                var share = new Share
                {
                    Id = Guid.NewGuid(),
                    OwnerUserId = owner.UserId,
                    UploaderEmail = owner.Email,
                    ShareToken = token,
                    ZipDisplayName = stored.EntryName,
                    ZipDiskPath = string.Empty,
                    ZipSizeBytes = stored.SizeBytes,
                    ShareExperienceType = ShareModes.ToStorageValue(ShareExperienceType.Archive),
                    AccessMode = ShareModes.ToStorageValue(ShareAccessMode.DirectLink),
                    ContentRootPath = shareContentRelativePath,
                    NotifyMode = "none",
                    ExpiresAtUtc = expiresAtUtc,
                    CreatedAtUtc = now,
                    PageTitle = stored.EntryName,
                    PageH1 = stored.EntryName,
                    PageDescription = string.Empty,
                    Files =
                    [
                        new ShareFile
                        {
                            Id = Guid.NewGuid(),
                            OriginalFilename = stored.EntryName,
                            StoredRelativePath = stored.StoredRelativePath,
                            RenderType = DetectRenderType(stored.EntryName),
                            OriginalSizeBytes = stored.SizeBytes,
                            DetectedContentType = ContentTypePolicy.FromFileName(stored.EntryName)
                        }
                    ]
                };

                db.Shares.Add(share);
                attemptedShareIds.Add(share.Id);
                try
                {
                    // The commit is the point of no return: never let a shutdown cancel it halfway, or the job could
                    // be requeued for a share that was in fact created and the re-run would create a second one.
                    await db.SaveChangesAsync(CancellationToken.None);
                    return new CreateShareResult(share.Id, token, share.ZipDisplayName, share.ExpiresAtUtc);
                }
                catch (DbUpdateException ex) when (IsShareTokenConflict(ex))
                {
                    logger.LogWarning(
                        "Share token conflict while creating direct link. share={TokenRef} uploader={Uploader} constraint={Constraint}",
                        LogSafe.Token(token),
                        command.UploaderEmail,
                        ShareTokenConflictConstraint(ex));
                    db.Entry(share).State = EntityState.Detached;
                    // Random collision on a generated token; retry with a new one.
                }
                catch
                {
                    db.Entry(share).State = EntityState.Detached;
                    throw;
                }
            }

            throw new InvalidOperationException("Unable to generate a unique share token right now.");
        }
        catch
        {
            if (await IsAnyShareCommittedAsync(attemptedShareIds))
            {
                logger.LogWarning(
                    "Direct link creation failed but a share row may have been committed (ids {ShareIds}); keeping its content root {ContentRoot} for reconciliation",
                    attemptedShareIds,
                    shareContentRelativePath);
            }
            else
            {
                await DeleteUploadedObjectsAsync(shareContentRelativePath, []);
            }

            throw;
        }
    }

    /// <summary>
    /// The single share file of a draft, for a direct link: the draft must hold exactly one staged share file, it
    /// must be the one the client named, and its extension must be one the content policy serves inline.
    /// </summary>
    public async Task<StagedUploadFile> ResolveDirectLinkUploadAsync(Guid ownerUserId, string draftShareId, string uploadId, CancellationToken cancellationToken)
    {
        if (!UploadIds.TryNormalize(uploadId, out var normalizedUploadId))
        {
            throw new InvalidOperationException("Uploaded file id is invalid.");
        }

        var staged = await ListStagedUploadsForDraftAsync(ownerUserId, draftShareId, cancellationToken);
        if (staged.Count != 1)
        {
            throw new InvalidOperationException(staged.Count == 0
                ? "Upload one file first."
                : "A direct link can hold only one file; remove the others or create a share link instead.");
        }

        var file = staged[0];
        if (!string.Equals(file.UploadId, normalizedUploadId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Uploaded file does not belong to this draft share.");
        }

        if (!ContentTypePolicy.Resolve(file.OriginalFileName).Inline)
        {
            throw new InvalidOperationException("This file type can only be downloaded, not opened directly; create a share link instead.");
        }

        return file;
    }

    private async Task<bool> IsAnyShareCommittedAsync(IReadOnlyList<Guid> shareIds)
    {
        if (shareIds.Count == 0)
        {
            return false;
        }

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using var fresh = (AgoraDbContext)Activator.CreateInstance(db.GetType(), db.GetService<IDbContextOptions>())!;
            return await fresh.Shares.AsNoTracking().AnyAsync(x => shareIds.Contains(x.Id), timeout.Token);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not verify whether failed share creation committed (ids {ShareIds})", shareIds);
            return true;
        }
    }

    /// <summary>
    /// Compensation for a failed share creation; uses its own timeout so a cancelled request still cleans up. Every
    /// deletion is attempted even when earlier ones fail; whatever could not be deleted is logged for reconciliation.
    /// </summary>
    private async Task DeleteUploadedObjectsAsync(string? contentRootPath, IReadOnlyList<string> keys)
    {
        using var cleanup = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var failed = new List<string>();
        var errors = new List<Exception>();
        async Task TryAsync(string target, Func<Task> delete)
        {
            try
            {
                await delete();
            }
            catch (Exception ex)
            {
                failed.Add(target);
                errors.Add(ex);
            }
        }

        await TryAsync(contentRootPath ?? "<none>", () => contentStore.DeleteContentRootAsync(contentRootPath, cleanup.Token));
        foreach (var key in keys)
        {
            await TryAsync(key, () => objectStore.DeleteAsync(key, cleanup.Token));
        }

        if (failed.Count > 0)
        {
            logger.LogError(
                new AggregateException(errors),
                "Failed to delete objects of a failed share creation; left behind: {FailedObjects}",
                failed);
        }
    }

    private static string ShareBackgroundKey(string zipRelativePath, string sourceName)
    {
        var extension = Path.GetExtension(sourceName);
        return $"{zipRelativePath[..zipRelativePath.LastIndexOf('/')]}/{Path.GetFileNameWithoutExtension(zipRelativePath)}-background{(string.IsNullOrWhiteSpace(extension) ? ".bin" : extension)}";
    }

    /// <summary>
    /// Token lookup for the public download routes (and the owner's created/status views): the share with its
    /// files, never its download events. Event counts come from the owner dashboard projection.
    /// </summary>
    public Task<Share?> FindByTokenAsync(string token, CancellationToken cancellationToken)
    {
        return db.Shares
            .Include(x => x.Files)
            .SingleOrDefaultAsync(x => x.ShareToken == token, cancellationToken);
    }

    /// <summary>
    /// Fresh, untracked read of whether the share can still be served (not deleted, not expired, owner not disabled).
    /// </summary>
    public async Task<bool> IsShareActiveAsync(Guid shareId, CancellationToken cancellationToken)
    {
        var state = await db.Shares
            .AsNoTracking()
            .Where(x => x.Id == shareId)
            .Select(x => new
            {
                x.DeletedAtUtc,
                x.ExpiresAtUtc,
                OwnerDisabled = db.Users.Any(u => u.Id == x.OwnerUserId && !u.IsEnabled)
            })
            .SingleOrDefaultAsync(cancellationToken);
        if (state is null)
        {
            return false;
        }

        var now = DateTime.UtcNow;
        return state.DeletedAtUtc is null && (state.ExpiresAtUtc is null || now < state.ExpiresAtUtc.Value) && !state.OwnerDisabled;
    }

    /// <summary>
    /// Whether a found, not deleted share answers like an expired one (410) on the anonymous routes: it expired, or
    /// the account that owns it is disabled. A disabled owner's shares serve again once the account is enabled;
    /// rows without an owner keep serving.
    /// </summary>
    public async Task<bool> IsGoneAsync(Share share, CancellationToken cancellationToken)
    {
        if (IsExpired(share, DateTime.UtcNow))
        {
            return true;
        }

        return await IsOwnerDisabledAsync(share, cancellationToken);
    }

    /// <summary>Whether the account that owns the share exists and is disabled (false for rows without an owner).</summary>
    public async Task<bool> IsOwnerDisabledAsync(Share share, CancellationToken cancellationToken) =>
        share.OwnerUserId is { } ownerUserId
        && await db.Users.AsNoTracking().AnyAsync(u => u.Id == ownerUserId && !u.IsEnabled, cancellationToken);

    public Task<Share?> FindByTokenForUploaderAsync(string token, ShareOwner owner, CancellationToken cancellationToken)
    {
        return SharesOwnedBy(owner)
            .SingleOrDefaultAsync(x => x.ShareToken == token, cancellationToken);
    }

    /// <summary>
    /// Rows are owned by user id and nothing else; a row whose owner id is null (never backfilled) belongs to no one.
    /// </summary>
    private IQueryable<Share> SharesOwnedBy(ShareOwner owner)
    {
        var userId = owner.UserId;
        return db.Shares.Where(x => x.OwnerUserId == userId);
    }

    private IQueryable<AccountTemplate> TemplatesOwnedBy(ShareOwner owner)
    {
        var userId = owner.UserId;
        return db.AccountTemplates.Where(x => x.OwnerUserId == userId);
    }

    private static ShareOwner OwnerOf(CreateShareCommand command) => ShareOwner.For(command.OwnerUserId, command.UploaderEmail);

    /// <summary>Lock key shared with account deletion (<c>AuthService.DeleteUserAsync</c>).</summary>
    public static string OwnerLockKey(Guid ownerUserId) => $"owner:{ownerUserId:N}";

    public Task<List<UserShareSummary>> ListRecentSharesForUploaderAsync(ShareOwner owner, int take, CancellationToken cancellationToken)
    {
        return SharesOwnedBy(owner)
            .AsNoTracking()
            .Where(x => x.DeletedAtUtc == null)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(take)
            .Select(x => new UserShareSummary(
                x.Id,
                x.ZipDisplayName,
                x.ZipSizeBytes,
                x.Files.Count,
                x.DownloadEvents.Count,
                x.CreatedAtUtc,
                x.ExpiresAtUtc,
                x.DeletedAtUtc,
                x.SenderName,
                x.SenderEmail,
                x.SenderMessage,
                x.AccessMode,
                x.Files
                    .Select(file => new ShareArchiveFileSummary(
                        file.OriginalFilename,
                        file.OriginalSizeBytes))
                    .ToList()))
            .ToListAsync(cancellationToken);
    }

    /// <summary>The most shares one batch delete accepts; the home list shows at most this many.</summary>
    public const int MaxBatchDeleteShares = 100;

    /// <summary>
    /// Soft-deletes one of the owner's shares and queues its file cleanup. The cleanup is queued on the first delete;
    /// for a share that is already deleted only when <paramref name="requeueCleanup"/> is set (a retry after a failed
    /// enqueue), so repeated calls cannot pile up cleanup jobs.
    /// </summary>
    public async Task<bool> DeleteShareAsync(Guid shareId, ShareOwner owner, CancellationToken cancellationToken, bool requeueCleanup = false)
    {
        var share = await SharesOwnedBy(owner).SingleOrDefaultAsync(x => x.Id == shareId, cancellationToken);
        if (share is null)
        {
            return false;
        }

        var firstDelete = share.DeletedAtUtc is null;
        if (firstDelete)
        {
            share.DeletedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }

        if (firstDelete || requeueCleanup)
        {
            backgroundJobs.Enqueue<ShareManager>(x => x.DeleteShareFilesAsync(shareId, CancellationToken.None));
        }

        return true;
    }

    /// <summary>
    /// Deletes several of the owner's shares. Returns null (and changes nothing) for more than
    /// <see cref="MaxBatchDeleteShares"/> distinct ids, otherwise the number of shares that were deleted or already were.
    /// </summary>
    public async Task<int?> DeleteSharesAsync(IReadOnlyCollection<Guid> shareIds, ShareOwner owner, CancellationToken cancellationToken)
    {
        var ids = shareIds.Distinct().ToArray();
        if (ids.Length > MaxBatchDeleteShares)
        {
            return null;
        }

        var deleted = 0;
        foreach (var shareId in ids)
        {
            if (await DeleteShareAsync(shareId, owner, cancellationToken))
            {
                deleted += 1;
            }
        }

        return deleted;
    }

    public async Task<bool> ReenableShareFor24HoursAsync(Guid shareId, ShareOwner owner, CancellationToken cancellationToken)
    {
        var share = await SharesOwnedBy(owner).SingleOrDefaultAsync(
            x => x.Id == shareId && x.DeletedAtUtc == null,
            cancellationToken);
        if (share is null)
        {
            return false;
        }

        // A direct link is purged at the first cleanup run after expiry and has no archive to re-enable.
        if (ShareModes.IsDirectLink(share.AccessMode))
        {
            return false;
        }

        var now = DateTime.UtcNow;
        if (share.ExpiresAtUtc is null || share.ExpiresAtUtc > now)
        {
            return false;
        }

        if (!ObjectKey.TryNormalize(share.ZipDiskPath, out var zipKey) || await objectStore.GetInfoAsync(zipKey, cancellationToken) is null)
        {
            return false;
        }

        share.ExpiresAtUtc = now.AddHours(24);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<string?> GetCopyableShareTokenAsync(Guid shareId, ShareOwner owner, CancellationToken cancellationToken)
    {
        var share = await SharesOwnedBy(owner).SingleOrDefaultAsync(
            x => x.Id == shareId && x.DeletedAtUtc == null,
            cancellationToken);
        if (share is null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(share.ShareToken))
        {
            return share.ShareToken;
        }

        // Backfill legacy rows with a missing token value.
        var generated = await GenerateUniqueShareTokenAsync(8, cancellationToken);
        share.ShareToken = generated;
        await db.SaveChangesAsync(cancellationToken);
        return generated;
    }

    public async Task<bool> IsShareTokenAvailableAsync(string token, CancellationToken cancellationToken)
    {
        // A link claimed by a pending creation is not free either.
        return !await db.Shares.AsNoTracking().AnyAsync(x => x.ShareToken == token, cancellationToken) &&
               !await db.ShareTokenReservations.AsNoTracking().AnyAsync(x => x.Token == token, cancellationToken);
    }

    /// <summary>
    /// The refusal shown to the owner for a share token they typed when creating a share, or null when it can be used.
    /// The in-use refusal suggests a freshly generated token instead.
    /// </summary>
    public async Task<string?> CheckRequestedShareTokenAsync(string token, CancellationToken cancellationToken, Guid? ownerUserId = null, string? draftShareId = null)
    {
        if (!ShareTokens.IsValid(token))
        {
            return "Share link must be 8-64 letters, numbers, hyphens, or underscores.";
        }

        // The submitting owner's own claim for this draft does not count against it (a repeated submission).
        var heldByCaller = ownerUserId is { } owner && draftShareId is not null &&
            await db.ShareTokenReservations.AsNoTracking().AnyAsync(x => x.Token == token && x.OwnerUserId == owner && x.DraftShareId == draftShareId, cancellationToken) &&
            !await db.Shares.AsNoTracking().AnyAsync(x => x.ShareToken == token, cancellationToken);
        if (!heldByCaller && !await IsShareTokenAvailableAsync(token, cancellationToken))
        {
            var suggested = await GenerateUniqueShareTokenAsync(8, cancellationToken);
            return $"That share link is already in use. Try {suggested} or choose another.";
        }

        return null;
    }

    public async Task<string> GenerateUniqueShareTokenAsync(int length, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 32; attempt += 1)
        {
            var token = TokenCodec.GenerateAlphanumericToken(length);
            if (await IsShareTokenAvailableAsync(token, cancellationToken))
            {
                return token;
            }
        }

        throw new InvalidOperationException("Unable to generate a unique share token right now.");
    }

    public async Task<ShareTokenDiagnostics> GetShareTokenDiagnosticsAsync(string token, CancellationToken cancellationToken)
    {
        var normalized = (token ?? string.Empty).Trim();
        var caseSensitiveMatchCount = await db.Shares.AsNoTracking()
            .CountAsync(x => x.ShareToken == normalized, cancellationToken);
        var lower = normalized.ToLowerInvariant();
        var caseInsensitiveMatchCount = await db.Shares.AsNoTracking()
            .CountAsync(x => x.ShareToken.ToLower() == lower, cancellationToken);
        var first = await db.Shares.AsNoTracking()
            .Where(x => x.ShareToken.ToLower() == lower)
            .OrderBy(x => x.CreatedAtUtc)
            .Select(x => new { x.Id, x.UploaderEmail, x.CreatedAtUtc })
            .FirstOrDefaultAsync(cancellationToken);

        return new ShareTokenDiagnostics(
            Token: normalized,
            Exists: caseSensitiveMatchCount > 0 || caseInsensitiveMatchCount > 0,
            CaseSensitiveMatchCount: caseSensitiveMatchCount,
            CaseInsensitiveMatchCount: caseInsensitiveMatchCount,
            ExistingShareId: first?.Id,
            ExistingShareUploader: first?.UploaderEmail,
            ExistingShareCreatedAtUtc: first?.CreatedAtUtc,
            DatabaseProvider: db.Database.ProviderName ?? "<unknown>");
    }

    public async Task DeleteShareFilesAsync(Guid shareId, CancellationToken cancellationToken)
    {
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(x => x.Id == shareId, cancellationToken);
        if (share is null)
        {
            return;
        }

        await DeleteShareContentFilesAsync(share, cancellationToken);
    }

    /// <summary>Soft-deleted by the owner or purged after expiry. Public routes answer 404.</summary>
    public static bool IsDeleted(Share share) => share.DeletedAtUtc is not null;

    /// <summary>Past its expiry (deleted shares are a separate state, see <see cref="IsDeleted"/>). Public routes answer 410.</summary>
    public static bool IsExpired(Share share, DateTime utcNow) =>
        share.ExpiresAtUtc is not null && utcNow >= share.ExpiresAtUtc.Value;

    /// <summary>Neither deleted nor expired: the share can be served.</summary>
    public static bool IsActive(Share share, DateTime utcNow) => !IsDeleted(share) && !IsExpired(share, utcNow);

    public async Task RecordDownloadAsync(Share share, string token, string ipAddress, string userAgent, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var metadata = BrowserMetadataParser.ToJson(userAgent);
        var mode = (share.NotifyMode ?? "none").Trim().ToLowerInvariant();

        var shouldSend = false;
        var coalesce = false;

        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
        if (mode == "once")
        {
            // Atomic conditional first-download update ensures only one notification is sent in concurrent requests.
            var affected = await db.Shares
                .Where(x => x.Id == share.Id && x.FirstDownloadedAtUtc == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.FirstDownloadedAtUtc, now), cancellationToken);
            shouldSend = affected == 1;
            if (affected == 1)
            {
                share.FirstDownloadedAtUtc = now;
            }
        }
        else if (mode == "every_time")
        {
            coalesce = true;
            if (share.FirstDownloadedAtUtc is null)
            {
                share.FirstDownloadedAtUtc = now;
            }
        }

        var downloadEvent = new DownloadEvent
        {
            Id = Guid.NewGuid(),
            ShareId = share.Id,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            BrowserMetadataJson = metadata,
            DownloadedAtUtc = now,
            NotificationSent = false
        };

        db.DownloadEvents.Add(downloadEvent);
        await db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);

        if (shouldSend)
        {
            backgroundJobs.Enqueue<EmailNotificationJob>(x =>
                x.ProcessDownloadEventAsync(downloadEvent.Id, token, CancellationToken.None, null));
        }
        else if (coalesce)
        {
            await QueueCoalescedNotificationAsync(share.Id, downloadEvent.Id, token, now, cancellationToken);
        }
    }

    /// <summary>
    /// <c>every_time</c> notifications send at most one email per share per
    /// <see cref="EmailNotificationJob.CoalesceWindow"/>, covering every download since the previous one. State lives
    /// in the download events: an event not yet notified (and without an error) means a job is pending. Otherwise the
    /// email goes out at once when the share had no other download within two windows (so no email can have been
    /// sent within the last window: a delayed job runs at most one window after its first download), else one window
    /// from now. A pending event older than two windows counts as lost and no longer blocks a new job.
    /// </summary>
    private async Task QueueCoalescedNotificationAsync(Guid shareId, Guid eventId, string token, DateTime now, CancellationToken cancellationToken)
    {
        var window = EmailNotificationJob.CoalesceWindow;
        var lookback = now - (window + window);
        // Only earlier downloads count (ties broken by id), so of two concurrent downloads exactly one queues the job.
        var recent = (await db.DownloadEvents
                .AsNoTracking()
                .Where(x => x.ShareId == shareId && x.Id != eventId && x.DownloadedAtUtc >= lookback && x.DownloadedAtUtc <= now)
                .Select(x => new { x.Id, x.DownloadedAtUtc, x.NotificationSent, x.NotificationError })
                .ToListAsync(cancellationToken))
            .Where(x => x.DownloadedAtUtc < now || x.Id.CompareTo(eventId) < 0)
            .ToList();

        if (recent.Any(x => !x.NotificationSent && x.NotificationError == null))
        {
            return;
        }

        if (recent.Count == 0)
        {
            backgroundJobs.Enqueue<EmailNotificationJob>(x =>
                x.ProcessShareDownloadsAsync(shareId, token, CancellationToken.None, null));
        }
        else
        {
            backgroundJobs.Schedule<EmailNotificationJob>(x =>
                x.ProcessShareDownloadsAsync(shareId, token, CancellationToken.None, null), window);
        }
    }

    public async Task UpsertAccountTemplateAsync(ShareOwner owner, ShareTemplateData template, CancellationToken cancellationToken)
    {
        var existing = await TemplatesOwnedBy(owner).FirstOrDefaultAsync(cancellationToken);
        var previousBackground = existing?.BackgroundImageUrl;
        if (existing is null)
        {
            db.AccountTemplates.Add(new AccountTemplate
            {
                Id = Guid.NewGuid(),
                OwnerUserId = owner.UserId,
                UploaderEmail = owner.Email,
                Title = template.Title,
                H1 = template.H1,
                Description = template.Description,
                BackgroundImageUrl = template.BackgroundImageUrl,
                BackgroundColorHex = template.BackgroundColorHex,
                ContainerPosition = NormalizeContainerPosition(template.ContainerPosition),
                UpdatedAtUtc = DateTime.UtcNow
            });
        }
        else
        {
            existing.Title = template.Title;
            existing.H1 = template.H1;
            existing.Description = template.Description;
            existing.BackgroundImageUrl = template.BackgroundImageUrl;
            existing.BackgroundColorHex = template.BackgroundColorHex;
            existing.ContainerPosition = NormalizeContainerPosition(template.ContainerPosition);
            existing.UpdatedAtUtc = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(cancellationToken);
        // Under the owner lock share creation holds while it reads the account template and copies its background,
        // so a creation that already read the old marker finishes its copy first.
        using (await draftLocks.LockAsync(OwnerLockKey(owner.UserId), cancellationToken))
        {
            await DeleteReplacedAccountBackgroundAsync(previousBackground, template.BackgroundImageUrl, cancellationToken);
        }
    }

    /// <summary>
    /// Removes the account background object a template no longer points to, once the new state is committed. Only
    /// <c>uploads/templates/</c> keys are touched, and only when no share or template row still references the
    /// marker (shares created before backgrounds were copied per share point at the account object directly).
    /// A failure is logged and leaves an orphan; the saved template is unaffected.
    /// </summary>
    private async Task DeleteReplacedAccountBackgroundAsync(string? previousMarker, string? currentMarker, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(previousMarker) || string.Equals(previousMarker, currentMarker, StringComparison.Ordinal))
        {
            return;
        }

        var key = ObjectKey.FromInternalMarker(previousMarker);
        if (key is null || !key.StartsWith("uploads/templates/", StringComparison.Ordinal))
        {
            return;
        }

        try
        {
            if (await db.Shares.AsNoTracking().AnyAsync(x => x.BackgroundImageUrl == previousMarker, cancellationToken) ||
                await db.AccountTemplates.AsNoTracking().AnyAsync(x => x.BackgroundImageUrl == previousMarker, cancellationToken))
            {
                return;
            }

            await objectStore.DeleteAsync(key, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Unable to delete the replaced account background {BackgroundKey}", key);
        }
    }

    public async Task<ShareTemplateData> GetAccountTemplateAsync(ShareOwner owner, CancellationToken cancellationToken)
    {
        var existing = await TemplatesOwnedBy(owner).AsNoTracking().FirstOrDefaultAsync(cancellationToken);
        if (existing is null)
        {
            return new ShareTemplateData(
                $"by {owner.Email}",
                "A file was shared with you",
                string.Empty,
                null,
                null,
                "center");
        }

        return new ShareTemplateData(
            existing.Title,
            existing.H1,
            existing.Description,
            existing.BackgroundImageUrl,
            existing.BackgroundColorHex,
            NormalizeContainerPosition(existing.ContainerPosition));
    }

    public async Task<int> CleanupExpiredSharesAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        // Ordinary shares keep a 7-day grace after expiry so the owner can "Re-enable 24h"; direct links cannot be
        // re-enabled and are purged at the first run after they expire.
        var purgeCutoff = now.AddDays(-7);
        var directLinkMode = ShareModes.ToStorageValue(ShareAccessMode.DirectLink);
        var expired = await db.Shares
            .Where(x => x.DeletedAtUtc == null && x.ExpiresAtUtc != null &&
                        (x.ExpiresAtUtc <= purgeCutoff || (x.AccessMode == directLinkMode && x.ExpiresAtUtc <= now)))
            .ToListAsync(cancellationToken);

        var count = 0;
        foreach (var share in expired)
        {
            await DeleteShareContentFilesAsync(share, cancellationToken);
            share.DeletedAtUtc = now;
            count++;
        }

        if (count > 0)
        {
            await db.SaveChangesAsync(cancellationToken);
        }

        var eventCutoff = now.AddDays(-Math.Abs(_options.DownloadEventRetentionDays));
        var oldEvents = await db.DownloadEvents.Where(x => x.DownloadedAtUtc < eventCutoff).ToListAsync(cancellationToken);
        if (oldEvents.Count > 0)
        {
            db.DownloadEvents.RemoveRange(oldEvents);
            await db.SaveChangesAsync(cancellationToken);
        }

        return count;
    }

    public async Task<StagedUploadFile> StageUploadAsync(
        Guid ownerUserId,
        string draftShareId,
        string originalFileName,
        long originalSizeBytes,
        Stream source,
        CancellationToken cancellationToken,
        string uploadPurpose = UploadPurposeShareFile)
    {
        var normalizedPurpose = NormalizeUploadPurpose(uploadPurpose);
        var isShareFile = string.Equals(normalizedPurpose, UploadPurposeShareFile, StringComparison.Ordinal);
        if (!TryNormalizeDraftShareId(draftShareId, out draftShareId))
        {
            throw new InvalidOperationException("draftShareId is invalid.");
        }

        // The whole stage runs under the draft lock, for every purpose: the draft is re-validated here because the
        // request was admitted before its body was buffered and the draft may have been finalized or swept since;
        // per-draft count and bytes are enforced on what is already on disk; the slot marker is claimed before the
        // payload is written; and the sweep (same lock) can never remove the draft underneath an upload.
        using (await draftLocks.LockAsync(DraftLockKey(draftShareId), cancellationToken))
        {
            var draft = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
            if (draft is null || draft.OwnerUserId != ownerUserId)
            {
                throw new UploadLimitException(UploadLimitKind.DraftClosed, "This upload is no longer open; reload the page to start a new one.");
            }

            if (IsDraftSealed(draftShareId))
            {
                throw new UploadLimitException(UploadLimitKind.DraftSealed, "This upload was already submitted; start a new one to send more files.");
            }

            string? markerDirectory = null;
            if (isShareFile)
            {
                var totals = ReadDraftStagedTotals(draftShareId, GetStagingRoot(normalizedPurpose));
                if (totals.Count >= _options.MaxFilesPerShare)
                {
                    throw new UploadLimitException(
                        UploadLimitKind.TooManyFiles,
                        $"Too many files. Max {_options.MaxFilesPerShare} per share.");
                }

                if (totals.Bytes + originalSizeBytes > _options.MaxTotalUploadBytes)
                {
                    throw new UploadLimitException(
                        UploadLimitKind.TooManyBytes,
                        $"Total upload size exceeds the limit of {FormatBytes(_options.MaxTotalUploadBytes)} per share.");
                }

                markerDirectory = GetDraftStagedIndexDirectory(draftShareId);
            }

            var budgetKind = await ResolveStageBudgetKindAsync(draft, cancellationToken);
            var staged = await WriteStagedUploadAsync(ownerUserId, draftShareId, originalFileName, originalSizeBytes, source, normalizedPurpose, markerDirectory, budgetKind, cancellationToken);
            await TouchDraftAsync(draftShareId, cancellationToken);
            return staged;
        }
    }

    /// <summary>Reserves scratch, streams the payload and writes metadata last (metadata present = upload complete).</summary>
    private async Task<StagedUploadFile> WriteStagedUploadAsync(
        Guid ownerUserId,
        string draftShareId,
        string originalFileName,
        long originalSizeBytes,
        Stream source,
        string normalizedPurpose,
        string? draftMarkerDirectory,
        StageBudgetKind budgetKind,
        CancellationToken cancellationToken)
    {
        using var reservation = scratchSpace.Reserve(originalSizeBytes);

        var uploadId = Guid.NewGuid().ToString("N");
        var stagingDirectory = Path.Combine(GetStagingRoot(normalizedPurpose), uploadId);
        var sanitizedName = ArchiveNameResolver.Sanitize(originalFileName);
        var payloadPath = Path.Combine(stagingDirectory, "payload.bin");
        var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
        var draftMarkerPath = draftMarkerDirectory is null ? null : Path.Combine(draftMarkerDirectory, uploadId);
        var budgetMarkerPath = budgetKind == StageBudgetKind.Unlimited
            ? null
            : Path.Combine(GetStagedIndexDirectory(budgetKind, ownerUserId), uploadId);

        StagedUploadMetadata metadata;
        try
        {
            if (budgetMarkerPath is not null)
            {
                // Check and claim in one short critical section per account (or for all anonymous drafts): the staging
                // directory and a marker holding the declared size are visible to the next check before the payload
                // streams in, so concurrent stages cannot both pass on the same remaining budget. The draft lock is
                // always taken first, this lock second, and nothing takes them the other way round.
                using (await draftLocks.LockAsync(StageBudgetLockKey(budgetKind, ownerUserId), cancellationToken))
                {
                    var limit = ReadStageBudget(budgetKind, ownerUserId);
                    if (originalSizeBytes > limit.Remaining)
                    {
                        throw limit.Refusal;
                    }

                    Directory.CreateDirectory(stagingDirectory);
                    Directory.CreateDirectory(Path.GetDirectoryName(budgetMarkerPath)!);
                    await File.WriteAllTextAsync(
                        budgetMarkerPath,
                        string.Join('|', normalizedPurpose, draftShareId, originalSizeBytes.ToString(CultureInfo.InvariantCulture)),
                        cancellationToken);
                }
            }

            Directory.CreateDirectory(stagingDirectory);
            if (draftMarkerPath is not null)
            {
                // The marker is valid while the staging directory exists; it holds the declared size.
                Directory.CreateDirectory(draftMarkerDirectory!);
                await File.WriteAllTextAsync(draftMarkerPath, originalSizeBytes.ToString(CultureInfo.InvariantCulture), cancellationToken);
            }

            await using (var destination = File.Create(payloadPath))
            {
                await source.CopyToAsync(destination, cancellationToken);
            }

            metadata = new StagedUploadMetadata(
                UploadId: uploadId,
                OwnerUserId: ownerUserId,
                DraftShareId: draftShareId,
                OriginalFileName: sanitizedName,
                OriginalSizeBytes: originalSizeBytes,
                // Derived from the extension only; the multipart Content-Type the client sent is never trusted.
                ContentType: ContentTypePolicy.FromFileName(sanitizedName),
                CreatedAtUtc: DateTime.UtcNow,
                UploadPurpose: normalizedPurpose);

            await File.WriteAllTextAsync(metadataPath, JsonSerializer.Serialize(metadata), cancellationToken);
            reservation.Commit();
        }
        catch
        {
            // Release the claimed slot and partial payload; the sweep would otherwise hold them for the retention.
            TryDeleteDirectory(stagingDirectory);
            ScratchFiles.TryDelete(draftMarkerPath);
            ScratchFiles.TryDelete(budgetMarkerPath);
            throw;
        }

        return new StagedUploadFile(
            UploadId: uploadId,
            OriginalFileName: metadata.OriginalFileName,
            OriginalSizeBytes: metadata.OriginalSizeBytes,
            ContentType: metadata.ContentType,
            TempPath: payloadPath,
            DirectoryPath: stagingDirectory);
    }

    public async Task<IReadOnlyList<StagedUploadFile>> ResolveStagedUploadsAsync(
        Guid ownerUserId,
        IReadOnlyCollection<string> uploadIds,
        string? expectedDraftShareId,
        CancellationToken cancellationToken,
        string requiredPurpose = UploadPurposeShareFile)
    {
        if (uploadIds.Count == 0)
        {
            return [];
        }

        var resolved = new List<StagedUploadFile>(uploadIds.Count);
        var normalizedPurpose = NormalizeUploadPurpose(requiredPurpose);

        foreach (var rawId in uploadIds)
        {
            if (string.IsNullOrWhiteSpace(rawId))
            {
                continue;
            }

            // Only a GUID ever reaches Path.Combine: anything else (traversal, absolute paths) is refused here.
            if (!UploadIds.TryNormalize(rawId, out var uploadId))
            {
                throw new InvalidOperationException("Uploaded file id is invalid.");
            }

            var stagingDirectory = Path.Combine(GetStagingRoot(normalizedPurpose), uploadId);
            var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
            var payloadPath = Path.Combine(stagingDirectory, "payload.bin");

            if (!Directory.Exists(stagingDirectory) || !File.Exists(metadataPath) || !File.Exists(payloadPath))
            {
                throw new InvalidOperationException($"Uploaded file '{uploadId}' is not available.");
            }

            StagedUploadMetadata? metadata;
            try
            {
                var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
            }
            catch
            {
                metadata = null;
            }

            if (metadata is null)
            {
                throw new InvalidOperationException($"Uploaded file '{uploadId}' has invalid metadata.");
            }

            if (metadata.OwnerUserId != ownerUserId)
            {
                throw new InvalidOperationException($"Uploaded file '{uploadId}' does not belong to the current user.");
            }

            if (!string.IsNullOrWhiteSpace(expectedDraftShareId) &&
                !string.Equals(metadata.DraftShareId, expectedDraftShareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Uploaded file '{uploadId}' does not belong to this draft share.");
            }

            var metadataPurpose = NormalizeUploadPurpose(metadata.UploadPurpose);
            if (!string.Equals(metadataPurpose, normalizedPurpose, StringComparison.Ordinal))
            {
                // Prevent cross-purpose reuse (for example template backgrounds as share files).
                throw new InvalidOperationException($"Uploaded file '{uploadId}' is not available for this operation.");
            }

            resolved.Add(new StagedUploadFile(
                UploadId: uploadId,
                OriginalFileName: metadata.OriginalFileName,
                OriginalSizeBytes: metadata.OriginalSizeBytes,
                ContentType: metadata.ContentType,
                TempPath: payloadPath,
                DirectoryPath: stagingDirectory));
        }

        return resolved;
    }

    public async Task<IReadOnlyList<StagedUploadFile>> ListStagedUploadsForDraftAsync(
        Guid ownerUserId,
        string draftShareId,
        CancellationToken cancellationToken)
    {
        var stagingRoot = GetStagingRoot(UploadPurposeShareFile);
        if (!Directory.Exists(stagingRoot))
        {
            return [];
        }
        var result = new List<StagedUploadFile>();
        foreach (var stagingDirectory in Directory.EnumerateDirectories(stagingRoot))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
            var payloadPath = Path.Combine(stagingDirectory, "payload.bin");
            if (!File.Exists(metadataPath) || !File.Exists(payloadPath))
            {
                continue;
            }

            StagedUploadMetadata? metadata;
            try
            {
                var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
            }
            catch
            {
                metadata = null;
            }

            if (metadata is null)
            {
                continue;
            }

            if (metadata.OwnerUserId != ownerUserId)
            {
                continue;
            }

            if (!string.Equals(metadata.DraftShareId, draftShareId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.Equals(NormalizeUploadPurpose(metadata.UploadPurpose), UploadPurposeShareFile, StringComparison.Ordinal))
            {
                continue;
            }

            result.Add(new StagedUploadFile(
                metadata.UploadId,
                metadata.OriginalFileName,
                metadata.OriginalSizeBytes,
                metadata.ContentType,
                payloadPath,
                stagingDirectory));
        }

        return result.OrderBy(x => x.OriginalFileName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<bool> DeleteStagedUploadAsync(
        Guid ownerUserId,
        string draftShareId,
        string uploadId,
        CancellationToken cancellationToken)
    {
        // Both ids are validated before they form a path; only share-file uploads of the caller's own, still open
        // draft can be removed through this route (a template background is never a share file).
        if (!UploadIds.TryNormalize(uploadId, out var normalizedUploadId) ||
            !TryNormalizeDraftShareId(draftShareId, out var normalizedDraftShareId))
        {
            return false;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedDraftShareId), cancellationToken))
        {
            if (IsDraftSealed(normalizedDraftShareId))
            {
                // Submitted: the queued job owns these files now.
                return false;
            }

            // Only the signed-in owner's own drafts; a public-upload draft answers like a missing upload.
            var draft = await ReadDraftMetadataAsync(normalizedDraftShareId, cancellationToken);
            if (draft is null || draft.OwnerUserId != ownerUserId || draft.PublicUpload)
            {
                return false;
            }

            var stagingDirectory = Path.Combine(GetStagingRoot(UploadPurposeShareFile), normalizedUploadId);
            var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
            var payloadPath = Path.Combine(stagingDirectory, "payload.bin");
            if (!Directory.Exists(stagingDirectory) || !File.Exists(metadataPath) || !File.Exists(payloadPath))
            {
                return false;
            }

            StagedUploadMetadata? metadata;
            try
            {
                var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
            }
            catch
            {
                metadata = null;
            }

            if (metadata is null ||
                metadata.OwnerUserId != ownerUserId ||
                !string.Equals(NormalizeUploadPurpose(metadata.UploadPurpose), UploadPurposeShareFile, StringComparison.Ordinal) ||
                !TryNormalizeDraftShareId(metadata.DraftShareId, out var metadataDraftShareId) ||
                !string.Equals(metadataDraftShareId, normalizedDraftShareId, StringComparison.Ordinal))
            {
                return false;
            }

            Directory.Delete(stagingDirectory, recursive: true);
            // Free the per-draft slot right away instead of waiting for the next count to notice.
            ScratchFiles.TryDelete(Path.Combine(GetDraftStagedIndexDirectory(normalizedDraftShareId), normalizedUploadId));
            return true;
        }
    }

    private sealed record DraftStagedTotals(int Count, long Bytes);

    private enum StageBudgetKind
    {
        Unlimited,
        /// <summary>A signed-in account's staged bytes across all its drafts (share files and backgrounds).</summary>
        Account,
        /// <summary>Bytes held in open anonymous drafts: per upload link and across all links.</summary>
        Public
    }

    /// <summary>Bytes still admitted under a budget and the refusal for a stage that does not fit.</summary>
    private sealed record StageBudgetLimit(long Remaining, UploadLimitException Refusal);

    private async Task<StageBudgetKind> ResolveStageBudgetKindAsync(DraftShareMetadata draft, CancellationToken cancellationToken)
    {
        if (draft.PublicUpload)
        {
            return StageBudgetKind.Public;
        }

        if (_options.MaxStagedBytesPerAccount <= 0 || draft.OwnerUserId is not { } ownerUserId)
        {
            return StageBudgetKind.Unlimited;
        }

        // The same role the admin policy checks ("admin"); read from the user record so cookie and API-token callers agree.
        var isAdmin = await db.Users.AsNoTracking().AnyAsync(x => x.Id == ownerUserId && x.Role == "admin", cancellationToken);
        return isAdmin ? StageBudgetKind.Unlimited : StageBudgetKind.Account;
    }

    private static string StageBudgetLockKey(StageBudgetKind kind, Guid ownerUserId) =>
        kind == StageBudgetKind.Public ? "stage-budget:public" : $"stage-budget:account:{ownerUserId:N}";

    private string GetStagedIndexDirectory(StageBudgetKind kind, Guid ownerUserId) =>
        Path.Combine(GetStagedIndexRoot(kind), ownerUserId.ToString("N"));

    private string GetStagedIndexRoot(StageBudgetKind kind) =>
        Path.Combine(_options.StorageRoot, "uploads", "staged-index", kind == StageBudgetKind.Public ? "public" : "account");

    private StageBudgetLimit ReadStageBudget(StageBudgetKind kind, Guid ownerUserId)
    {
        if (kind == StageBudgetKind.Account)
        {
            var cap = _options.MaxStagedBytesPerAccount;
            return new StageBudgetLimit(
                Math.Max(0, cap - SumStagedIndex(kind, ownerUserId)),
                new UploadLimitException(
                    UploadLimitKind.TooManyBytes,
                    $"Your account already holds the limit of {FormatBytes(cap)} in staged uploads. Submit or remove some first."));
        }

        var limits = _options.PublicUploads;
        var budget = scratchSpace.ScratchBudgetBytes;
        var linkCapped = limits.MaxOpenDraftBytesPerToken > 0;
        var globalCapped = limits.MaxOpenDraftScratchFraction > 0 && budget > 0;
        var (linkUsed, globalUsed) = linkCapped || globalCapped ? SumPublicStagedIndex(ownerUserId) : (0L, 0L);

        var linkRemaining = linkCapped ? Math.Max(0, limits.MaxOpenDraftBytesPerToken - linkUsed) : long.MaxValue;
        var globalRemaining = long.MaxValue;
        if (globalCapped)
        {
            var globalCap = (long)(Math.Min(1.0, limits.MaxOpenDraftScratchFraction) * budget);
            globalRemaining = Math.Max(0, globalCap - globalUsed);
        }

        // The global cap is a server-wide condition (507); the per-link cap is about this link's own uploads (413).
        return globalRemaining <= linkRemaining
            ? new StageBudgetLimit(globalRemaining, new UploadLimitException(
                UploadLimitKind.InsufficientStorage,
                "The server is out of storage space for uploads right now. Please try again later."))
            : new StageBudgetLimit(linkRemaining, new UploadLimitException(
                UploadLimitKind.TooManyBytes,
                "This upload link already holds too many pending uploads. Please try again later."));
    }

    /// <summary>
    /// Bytes still staged by one account. Markers whose staging directory is gone are dropped. Cost is one small
    /// file read and one directory check per staged upload of that account.
    /// </summary>
    private long SumStagedIndex(StageBudgetKind kind, Guid ownerUserId)
    {
        long total = 0;
        foreach (var (_, size) in EnumerateStagedMarkers(Path.Combine(GetStagedIndexRoot(kind), ownerUserId.ToString("N"))))
        {
            total += size;
        }

        return total;
    }

    /// <summary>
    /// Bytes held in open anonymous drafts by one upload link and by all links, in a single pass over the index
    /// (submitted, sealed drafts are not counted). Cost is one small file read, one directory check and one file
    /// check per open anonymous upload, taken under the global anonymous budget lock.
    /// </summary>
    private (long Link, long Global) SumPublicStagedIndex(Guid ownerUserId)
    {
        var root = GetStagedIndexRoot(StageBudgetKind.Public);
        if (!Directory.Exists(root))
        {
            return (0, 0);
        }

        var ownerDirectory = ownerUserId.ToString("N");
        long link = 0, global = 0;
        foreach (var directory in Directory.EnumerateDirectories(root))
        {
            var isLink = string.Equals(Path.GetFileName(directory), ownerDirectory, StringComparison.Ordinal);
            foreach (var (draftShareId, size) in EnumerateStagedMarkers(directory))
            {
                if (IsDraftSealed(draftShareId))
                {
                    continue;
                }

                global += size;
                if (isLink)
                {
                    link += size;
                }
            }
        }

        return (link, global);
    }

    private IEnumerable<(string DraftShareId, long Size)> EnumerateStagedMarkers(string directory)
    {
        if (!Directory.Exists(directory))
        {
            yield break;
        }

        foreach (var markerPath in Directory.EnumerateFiles(directory))
        {
            if (TryReadStagedMarker(markerPath, out var draftShareId, out var size))
            {
                yield return (draftShareId, size);
            }
        }
    }

    /// <summary>Parses a staged-index marker; a malformed one or one whose staging directory is gone is deleted.</summary>
    private bool TryReadStagedMarker(string markerPath, out string draftShareId, out long size)
    {
        draftShareId = string.Empty;
        size = 0;
        try
        {
            var parts = File.ReadAllText(markerPath).Split('|');
            var uploadId = Path.GetFileName(markerPath);
            if (parts.Length == 3 &&
                Guid.TryParseExact(uploadId, "N", out _) &&
                long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out size) &&
                Directory.Exists(Path.Combine(GetStagingRoot(NormalizeUploadPurpose(parts[0])), uploadId)))
            {
                draftShareId = parts[1];
                size = Math.Max(0, size);
                return true;
            }
        }
        catch (IOException)
        {
            // Removed while being read; nothing to count.
            return false;
        }

        // A marker is written in place, so a fresh one may be read half-written by a sweep; only older ones are dropped.
        if (File.GetLastWriteTimeUtc(markerPath) < DateTime.UtcNow.AddMinutes(-5))
        {
            ScratchFiles.TryDelete(markerPath);
        }

        return false;
    }

    /// <summary>Drops staged-index markers whose staging directory is gone, and owner directories left empty.</summary>
    private int SweepStagedIndex(CancellationToken cancellationToken)
    {
        var removed = 0;
        foreach (var kind in new[] { StageBudgetKind.Account, StageBudgetKind.Public })
        {
            var root = GetStagedIndexRoot(kind);
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (var ownerDirectory in Directory.EnumerateDirectories(root))
            {
                foreach (var markerPath in Directory.EnumerateFiles(ownerDirectory))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!TryReadStagedMarker(markerPath, out _, out _))
                    {
                        removed++;
                    }
                }

                if (!Directory.EnumerateFileSystemEntries(ownerDirectory).Any())
                {
                    TryDeleteDirectory(ownerDirectory);
                }
            }
        }

        return removed;
    }

    /// <summary>What a staging budget still admits; <see cref="Refusal"/> is what to answer when a body does not fit.</summary>
    public sealed record StageBudget(long Remaining, UploadLimitException? Refusal)
    {
        public static StageBudget Unlimited { get; } = new(long.MaxValue, null);
    }

    /// <summary>
    /// The budget of the draft's owner (or, for an anonymous draft, its upload link and the server). Throws when it
    /// is exhausted: 413 for an account or link, 507 for the server-wide anonymous cap. Advisory, for sizing the
    /// request buffer; <see cref="StageUploadAsync"/> enforces it again under a lock. Call after the caller's
    /// ownership of the draft was checked.
    /// </summary>
    public async Task<StageBudget> GetStageBudgetAsync(string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId) ||
            await ReadDraftMetadataAsync(normalizedId, cancellationToken) is not { OwnerUserId: { } ownerUserId } draft)
        {
            return StageBudget.Unlimited;
        }

        var kind = await ResolveStageBudgetKindAsync(draft, cancellationToken);
        return kind == StageBudgetKind.Unlimited ? StageBudget.Unlimited : ReadBudgetOrThrow(kind, ownerUserId);
    }

    /// <summary>
    /// The anonymous budget of an upload link, before any draft is opened, so that an exhausted budget refuses a stage
    /// without creating an empty draft that would count against the open-draft caps. Throws like
    /// <see cref="GetStageBudgetAsync"/>.
    /// </summary>
    public StageBudget GetPublicStageBudget(Guid linkOwnerUserId) => ReadBudgetOrThrow(StageBudgetKind.Public, linkOwnerUserId);

    private StageBudget ReadBudgetOrThrow(StageBudgetKind kind, Guid ownerUserId)
    {
        var limit = ReadStageBudget(kind, ownerUserId);
        return limit.Remaining > 0 ? new StageBudget(limit.Remaining, limit.Refusal) : throw limit.Refusal;
    }

    /// <summary>
    /// Looks up (never creates, never touches) the open anonymous draft of an upload link. Throws when it does not
    /// exist or belongs to someone else, and when it was already submitted.
    /// </summary>
    public async Task<string> FindPublicUploadDraftAsync(Guid ownerUserId, string? draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId) ||
            await ReadDraftMetadataAsync(normalizedId, cancellationToken) is not { PublicUpload: true } draft ||
            draft.OwnerUserId != ownerUserId)
        {
            throw new UploadLimitException(UploadLimitKind.DraftClosed, "This upload is no longer open; reload the page to start a new one.");
        }

        if (IsDraftSealed(normalizedId))
        {
            throw new UploadLimitException(UploadLimitKind.DraftSealed, "This upload was already submitted; start a new one to send more files.");
        }

        return normalizedId;
    }

    /// <summary>
    /// Bytes still allowed into a draft's share files: the per-share total minus what is already staged. Call only
    /// after the caller's ownership of the draft was checked (<see cref="EnsureDraftShareAsync"/>).
    /// </summary>
    public long GetDraftRemainingShareBytes(string draftShareId)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return 0;
        }

        var staged = ReadDraftStagedTotals(normalizedId, GetStagingRoot(UploadPurposeShareFile)).Bytes;
        return Math.Max(0, _options.MaxTotalUploadBytes - staged);
    }

    /// <summary>
    /// Files and bytes currently staged for a draft, read from the per-draft slot markers. A marker whose staging
    /// directory is gone (removed, swept or finalized) is dropped on the spot.
    /// </summary>
    private DraftStagedTotals ReadDraftStagedTotals(string draftShareId, string stagingRoot)
    {
        var indexDirectory = GetDraftStagedIndexDirectory(draftShareId);
        if (!Directory.Exists(indexDirectory))
        {
            return new DraftStagedTotals(0, 0);
        }

        var count = 0;
        long bytes = 0;
        foreach (var markerPath in Directory.EnumerateFiles(indexDirectory))
        {
            var uploadId = Path.GetFileName(markerPath);
            if (!Guid.TryParseExact(uploadId, "N", out _) || !Directory.Exists(Path.Combine(stagingRoot, uploadId)))
            {
                ScratchFiles.TryDelete(markerPath);
                continue;
            }

            count++;
            try
            {
                if (long.TryParse(File.ReadAllText(markerPath), NumberStyles.Integer, CultureInfo.InvariantCulture, out var size))
                {
                    bytes += Math.Max(0, size);
                }
            }
            catch (IOException)
            {
                // Unreadable marker: the file still counts, its bytes do not.
            }
        }

        return new DraftStagedTotals(count, bytes);
    }

    /// <summary>
    /// Opens (or touches) the draft an anonymous visitor stages into through an upload link. A new draft counts
    /// against the open-draft caps of the upload code and of the client address; an existing draft is just touched.
    /// </summary>
    public async Task<string> EnsurePublicUploadDraftAsync(
        Guid ownerUserId,
        string? requestedDraftShareId,
        string uploadToken,
        string clientAddress,
        CancellationToken cancellationToken)
    {
        if (TryNormalizeDraftShareId(requestedDraftShareId, out var existingId) &&
            await ReadDraftMetadataAsync(existingId, cancellationToken) is { } existing &&
            existing.LastActivityUtc > DateTime.UtcNow - DraftRetention(existing.PublicUpload))
        {
            // Already open and counted; this also verifies ownership and refuses sealed drafts. A draft idle for
            // longer than the retention is not counted any more, so reviving it goes through admission again.
            return await EnsureDraftShareAsync(ownerUserId, existingId, cancellationToken, publicUpload: true);
        }

        var tokenHash = Sha256Hex(uploadToken.Trim());
        var addressHash = Sha256Hex(string.IsNullOrWhiteSpace(clientAddress) ? "unknown" : clientAddress.Trim());
        var limits = _options.PublicUploads;
        using (await draftLocks.LockAsync("public-upload-drafts", cancellationToken))
        {
            if (limits.MaxOpenDraftsPerToken > 0 &&
                await CountOpenDraftsAsync(GetDraftIndexDirectory("token", tokenHash), cancellationToken) >= limits.MaxOpenDraftsPerToken)
            {
                throw new UploadLimitException(
                    UploadLimitKind.TooManyOpenDrafts,
                    "This upload link has too many uploads in progress. Please try again later.");
            }

            if (limits.MaxOpenDraftsPerIp > 0 &&
                await CountOpenDraftsAsync(GetDraftIndexDirectory("ip", addressHash), cancellationToken) >= limits.MaxOpenDraftsPerIp)
            {
                throw new UploadLimitException(
                    UploadLimitKind.TooManyOpenDrafts,
                    "Too many uploads are in progress from your network. Please try again later.");
            }

            var draftShareId = await EnsureDraftShareAsync(ownerUserId, requestedDraftShareId, cancellationToken, publicUpload: true);
            WriteDraftIndexMarker("token", tokenHash, draftShareId);
            WriteDraftIndexMarker("ip", addressHash, draftShareId);
            return draftShareId;
        }
    }

    /// <summary>Shares this account received through its upload link since <paramref name="sinceUtc"/>, with their total original bytes.</summary>
    public async Task<ReceivedShareUsage> GetReceivedShareUsageAsync(ShareOwner owner, DateTime sinceUtc, CancellationToken cancellationToken)
    {
        // Received shares are the ones carrying a sender address; deleted ones still count (the cost was incurred).
        var received = SharesOwnedBy(owner).Where(x => x.SenderEmail != null && x.CreatedAtUtc >= sinceUtc);
        var count = await received.CountAsync(cancellationToken);
        if (count == 0)
        {
            return new ReceivedShareUsage(0, 0);
        }

        var bytes = await received.SelectMany(x => x.Files).SumAsync(x => x.OriginalSizeBytes, cancellationToken);
        return new ReceivedShareUsage(count, bytes);
    }

    public sealed record ReceivedShareUsage(int Count, long Bytes);

    private async Task<int> CountOpenDraftsAsync(string indexDirectory, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(indexDirectory))
        {
            return 0;
        }

        var cutoff = DateTime.UtcNow - DraftRetention(publicUpload: true);
        var open = 0;
        foreach (var markerPath in Directory.EnumerateFiles(indexDirectory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var draftShareId = Path.GetFileName(markerPath);
            if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId) || !Directory.Exists(GetDraftDirectory(normalizedId)))
            {
                ScratchFiles.TryDelete(markerPath);
                continue;
            }

            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            var lastActivityUtc = metadata?.LastActivityUtc ?? Directory.GetLastWriteTimeUtc(GetDraftDirectory(normalizedId));
            if (lastActivityUtc > cutoff)
            {
                open++;
            }
        }

        return open;
    }

    /// <summary>
    /// Marks the draft as submitted: nothing can be staged into it afterwards and a second submission is refused.
    /// Returns false when it was already sealed.
    /// </summary>
    public async Task<bool> SealDraftAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken, string? submittedShareToken = null)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            throw new InvalidOperationException("draftShareId is invalid.");
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            if (metadata is null || metadata.OwnerUserId != ownerUserId)
            {
                throw new InvalidOperationException("Draft share does not belong to the current user.");
            }

            if (IsDraftSealed(normalizedId))
            {
                return false;
            }

            // Submission starts the processing lease: the sweep keeps a sealed draft while its lease is fresh, and the
            // queued job renews it at every stage.
            var sealedAt = DateTime.UtcNow;
            await WriteDraftMetadataAsync(metadata with { LastActivityUtc = sealedAt, ProcessingLeaseUtc = sealedAt }, cancellationToken);
            // Line 1: when it was sealed. Line 2 (optional): the share link the sealing submission asked for.
            var sealText = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture) + (submittedShareToken is null ? string.Empty : "\n" + submittedShareToken);
            await File.WriteAllTextAsync(GetDraftSealPath(normalizedId), sealText, cancellationToken);
            return true;
        }
    }

    /// <summary>The share link the submission that sealed the draft asked for, or null when unknown.</summary>
    public async Task<string?> ReadDraftSealedShareTokenAsync(string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return null;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            try
            {
                var lines = await File.ReadAllLinesAsync(GetDraftSealPath(normalizedId), cancellationToken);
                return lines.Length > 1 && lines[1].Length > 0 ? lines[1] : null;
            }
            catch (IOException)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Seals the draft and runs <paramref name="enqueue"/> (the Hangfire enqueue). Returns false when the draft was
    /// already submitted. If enqueueing throws the seal is removed again so the sender can retry, and the failure is
    /// reported as a retryable 503.
    /// </summary>
    public async Task<bool> SealDraftForSubmissionAsync(Guid ownerUserId, string draftShareId, Func<Task> enqueue, CancellationToken cancellationToken, string? submittedShareToken = null)
    {
        if (!await SealDraftAsync(ownerUserId, draftShareId, cancellationToken, submittedShareToken))
        {
            return false;
        }

        try
        {
            await enqueue();
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Queueing share creation for draft {DraftShareId} failed; the draft was unsealed for a retry", draftShareId);
            await UnsealDraftAsync(ownerUserId, draftShareId, CancellationToken.None);
            throw new UploadLimitException(
                UploadLimitKind.QueueUnavailable,
                "The upload could not be queued for processing right now. Please try again in a moment.");
        }
    }

    public async Task UnsealDraftAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            if (metadata is not null && metadata.OwnerUserId == ownerUserId)
            {
                ScratchFiles.TryDelete(GetDraftSealPath(normalizedId));
            }
        }
    }

    /// <summary>
    /// Removes everything a draft left in scratch: every staged upload that references it (submitted or not, any
    /// purpose), its slot markers and the draft directory itself. Open-draft index markers go stale and are swept.
    /// </summary>
    public async Task<int> FinalizeDraftAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return 0;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var removed = await DeleteStagedUploadsForDraftAsync(ownerUserId, normalizedId, cancellationToken);
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            if (metadata is not null && metadata.OwnerUserId == ownerUserId)
            {
                TryDeleteDirectory(GetDraftDirectory(normalizedId));
            }

            return removed;
        }
    }

    public bool IsDraftSealed(string draftShareId)
    {
        return TryNormalizeDraftShareId(draftShareId, out var normalizedId) && File.Exists(GetDraftSealPath(normalizedId));
    }

    private string GetDraftSealPath(string draftShareId) => Path.Combine(GetDraftDirectory(draftShareId), "sealed");

    private static string DraftLockKey(string draftShareId) => $"draft:{draftShareId}";

    private TimeSpan DraftRetention(bool publicUpload)
    {
        var hours = publicUpload ? _options.PublicUploads.DraftRetentionHours : _options.ZombieUploadRetentionHours;
        return TimeSpan.FromHours(Math.Abs(hours));
    }

    /// <summary>
    /// Renews the processing lease of a sealed draft. The queued job calls this at each stage (start, after the share
    /// is persisted, before scratch cleanup); the sweep leaves a sealed draft alone while its lease is younger than
    /// the retention window, whatever the age of its uploads.
    /// </summary>
    public async Task RenewProcessingLeaseAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            if (metadata is not null && metadata.OwnerUserId == ownerUserId)
            {
                var now = DateTime.UtcNow;
                await WriteDraftMetadataAsync(metadata with { LastActivityUtc = now, ProcessingLeaseUtc = now }, cancellationToken);
            }
        }
    }

    /// <summary>Refreshes the draft's last activity (caller holds the draft lock).</summary>
    private async Task TouchDraftAsync(string draftShareId, CancellationToken cancellationToken)
    {
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is not null)
        {
            await WriteDraftMetadataAsync(metadata with { LastActivityUtc = DateTime.UtcNow }, cancellationToken);
        }
    }

    private string GetDraftIndexDirectory(string kind, string hash)
    {
        return Path.Combine(_options.StorageRoot, "uploads", "draft-index", kind, hash);
    }

    private void WriteDraftIndexMarker(string kind, string hash, string draftShareId)
    {
        var directory = Directory.CreateDirectory(GetDraftIndexDirectory(kind, hash)).FullName;
        File.WriteAllText(Path.Combine(directory, draftShareId), string.Empty);
    }

    /// <summary>Removes draft-index markers whose draft is gone and the hash directories left empty by that.</summary>
    private int SweepDraftIndex(CancellationToken cancellationToken)
    {
        var indexRoot = Path.Combine(_options.StorageRoot, "uploads", "draft-index");
        if (!Directory.Exists(indexRoot))
        {
            return 0;
        }

        var removed = 0;
        foreach (var kindDirectory in Directory.EnumerateDirectories(indexRoot))
        {
            foreach (var hashDirectory in Directory.EnumerateDirectories(kindDirectory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var markerPath in Directory.EnumerateFiles(hashDirectory))
                {
                    var draftShareId = Path.GetFileName(markerPath);
                    if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId) || !Directory.Exists(GetDraftDirectory(normalizedId)))
                    {
                        ScratchFiles.TryDelete(markerPath);
                        removed++;
                    }
                }

                if (!Directory.EnumerateFileSystemEntries(hashDirectory).Any())
                {
                    TryDeleteDirectory(hashDirectory);
                }
            }
        }

        return removed;
    }

    private static string Sha256Hex(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private static string FormatBytes(long bytes)
    {
        const long gb = 1024L * 1024 * 1024;
        const long mb = 1024L * 1024;
        return bytes >= gb
            ? $"{bytes / (double)gb:0.#} GB"
            : $"{Math.Max(1, bytes / mb)} MB";
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Swept later by the zombie cleanup.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    public Task<int> DeleteStagedUploadsForDraftAsync(
        Guid ownerUserId,
        string draftShareId,
        CancellationToken cancellationToken) =>
        DeleteStagedUploadsForDraftCoreAsync(ownerUserId, draftShareId, cancellationToken);

    /// <summary>A null owner skips the ownership check; only the zombie sweep uses that, so legacy drafts can still be swept.</summary>
    private async Task<int> DeleteStagedUploadsForDraftCoreAsync(
        Guid? ownerUserId,
        string draftShareId,
        CancellationToken cancellationToken)
    {
        var normalizedDraftShareId = (draftShareId ?? string.Empty).Trim();
        if (normalizedDraftShareId.Length == 0)
        {
            return 0;
        }

        var removed = 0;
        foreach (var stagingRoot in GetAllStagingRoots())
        {
            if (!Directory.Exists(stagingRoot))
            {
                continue;
            }

            foreach (var stagingDirectory in Directory.EnumerateDirectories(stagingRoot))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
                if (!File.Exists(metadataPath))
                {
                    continue;
                }

                StagedUploadMetadata? metadata;
                try
                {
                    var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                    metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
                }
                catch
                {
                    metadata = null;
                }

                if (metadata is null)
                {
                    continue;
                }

                if (ownerUserId is not null && metadata.OwnerUserId != ownerUserId)
                {
                    continue;
                }

                if (!string.Equals(metadata.DraftShareId, normalizedDraftShareId, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                Directory.Delete(stagingDirectory, recursive: true);
                removed++;
            }
        }

        return removed;
    }

    public async Task<int> CleanupZombieUploadsAsync(CancellationToken cancellationToken)
    {
        var staleDrafts = await CleanupStaleDraftSharesAsync(cancellationToken);
        var cutoff = DateTime.UtcNow.AddHours(-Math.Abs(_options.ZombieUploadRetentionHours));
        await SweepStaleShareTokenReservationsAsync(cutoff, cancellationToken);
        var removed = 0;
        foreach (var stagingRoot in GetAllStagingRoots())
        {
            if (!Directory.Exists(stagingRoot))
            {
                continue;
            }

            foreach (var stagingDirectory in Directory.EnumerateDirectories(stagingRoot))
            {
                cancellationToken.ThrowIfCancellationRequested();

                var metadataPath = Path.Combine(stagingDirectory, "metadata.json");
                var createdAtUtc = Directory.GetCreationTimeUtc(stagingDirectory);

                if (File.Exists(metadataPath))
                {
                    StagedUploadMetadata? metadata = null;
                    try
                    {
                        var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                        metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
                    }
                    catch
                    {
                        // Keep fallback timestamp when metadata cannot be parsed.
                    }

                    if (metadata is not null)
                    {
                        createdAtUtc = metadata.CreatedAtUtc;
                        // A complete upload that still has its draft lives and dies with that draft: the stale-draft
                        // sweep above removes it under the draft lock once the draft is idle (a queued job that is
                        // reading it keeps the draft active). Only orphans (draft gone) are aged out here.
                        if (TryNormalizeDraftShareId(metadata.DraftShareId, out var draftShareId) &&
                            Directory.Exists(GetDraftDirectory(draftShareId)))
                        {
                            continue;
                        }
                    }
                }

                // A directory without metadata is either an upload still streaming in (payload first, metadata last)
                // or a crashed one; only age tells them apart, so incomplete directories are swept by age.
                if (createdAtUtc <= cutoff)
                {
                    Directory.Delete(stagingDirectory, recursive: true);
                    removed++;
                }
            }
        }

        return removed + staleDrafts + SweepStaleScratchFiles(cutoff, cancellationToken) + SweepDraftIndex(cancellationToken) + SweepStagedIndex(cancellationToken);
    }

    /// <summary>
    /// Deletes scratch files (under tmp/, including ASP.NET's tmp/aspnet buffers), share-creation status files and
    /// preview .lock markers older than the cutoff. Only files are removed, so in-use directories such as tmp/aspnet survive.
    /// </summary>
    private int SweepStaleScratchFiles(DateTime cutoffUtc, CancellationToken cancellationToken)
    {
        var candidates = new[]
        {
            (Root: ScratchFiles.Root(_options.StorageRoot), Pattern: "*"),
            (Root: Path.Combine(_options.StorageRoot, "uploads", "share-create-status"), Pattern: "*.json"),
            (Root: Path.Combine(_options.StorageRoot, "previews"), Pattern: "*.lock")
        };

        var removed = 0;
        foreach (var (root, pattern) in candidates)
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (var path in Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (File.GetLastWriteTimeUtc(path) <= cutoffUtc)
                {
                    ScratchFiles.TryDelete(path);
                    removed++;
                }
            }
        }

        return removed;
    }

    public async Task<string> EnsureDraftShareAsync(
        Guid ownerUserId,
        string? requestedDraftShareId,
        CancellationToken cancellationToken,
        bool publicUpload = false)
    {
        var draftShareId = TryNormalizeDraftShareId(requestedDraftShareId, out var normalizedId)
            ? normalizedId
            : Guid.NewGuid().ToString("N");
        using (await draftLocks.LockAsync(DraftLockKey(draftShareId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
            // A draft opened through an upload link is never usable by the signed-in endpoints and vice versa; the
            // mismatch is refused exactly like someone else's draft, so neither side learns the other kind exists.
            if (metadata is not null && (metadata.OwnerUserId != ownerUserId || metadata.PublicUpload != publicUpload))
            {
                throw new InvalidOperationException("Draft share does not belong to the current user.");
            }

            if (metadata is not null && IsDraftSealed(draftShareId))
            {
                throw new UploadLimitException(UploadLimitKind.DraftSealed, "This upload was already submitted; start a new one to send more files.");
            }

            if (metadata is not null)
            {
                // Opening an existing draft never refreshes it: only staging bytes does (StageUploadAsync), so a page
                // that stays open or a refused request cannot keep an idle draft and its staged files alive.
                return draftShareId;
            }

            await WriteDraftMetadataAsync(
                new DraftShareMetadata(
                    DraftShareId: draftShareId,
                    OwnerUserId: ownerUserId,
                    LastActivityUtc: DateTime.UtcNow,
                    TemplateMode: "account_default",
                    Title: string.Empty,
                    H1: string.Empty,
                    Description: string.Empty,
                    BackgroundImageUrl: null,
                    BackgroundUploadId: null,
                    BackgroundColorHex: null,
                    ContainerPosition: "center",
                    PublicUpload: publicUpload),
                cancellationToken);
            return draftShareId;
        }
    }

    /// <summary>
    /// Read-only check for signed-in read paths: the draft exists, belongs to the caller and was not opened through an
    /// upload link. Nothing is created or touched.
    /// </summary>
    public async Task<bool> IsOwnSignedInDraftAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken) =>
        TryNormalizeDraftShareId(draftShareId, out var normalizedId) &&
        await ReadDraftMetadataAsync(normalizedId, cancellationToken) is { PublicUpload: false } metadata &&
        metadata.OwnerUserId == ownerUserId;

    public async Task<DraftTemplateState> GetDraftTemplateAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is null || metadata.OwnerUserId != ownerUserId || metadata.PublicUpload)
        {
            return new DraftTemplateState(draftShareId, "account_default", string.Empty, string.Empty, string.Empty, null, null, null, "center");
        }

        // A read: viewing the draft (new-share page, designer) must not refresh its activity.
        var updated = metadata;
        return new DraftTemplateState(
            draftShareId,
            string.IsNullOrWhiteSpace(updated.TemplateMode) ? "account_default" : updated.TemplateMode,
            updated.Title,
            updated.H1,
            updated.Description,
            updated.BackgroundImageUrl,
            updated.BackgroundUploadId,
            updated.BackgroundColorHex,
            NormalizeContainerPosition(updated.ContainerPosition));
    }

    public async Task SaveDraftTemplateAsync(
        Guid ownerUserId,
        string draftShareId,
        string templateMode,
        ShareTemplateData template,
        string? backgroundUploadId,
        CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            throw new InvalidOperationException("draftShareId is invalid.");
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            // Only signed-in drafts carry a per-share design; a public-upload draft is refused like someone else's.
            if (metadata is not null && (metadata.OwnerUserId != ownerUserId || metadata.PublicUpload))
            {
                throw new InvalidOperationException("Draft share does not belong to the current user.");
            }

            var next = new DraftShareMetadata(
                DraftShareId: normalizedId,
                OwnerUserId: ownerUserId,
                // Saving the design is not staging: an existing draft keeps its activity time and lease.
                LastActivityUtc: metadata?.LastActivityUtc ?? DateTime.UtcNow,
                TemplateMode: string.Equals(templateMode, "per_upload", StringComparison.OrdinalIgnoreCase) ? "per_upload" : "account_default",
                Title: template.Title,
                H1: template.H1,
                Description: template.Description,
                BackgroundImageUrl: template.BackgroundImageUrl,
                BackgroundUploadId: string.IsNullOrWhiteSpace(backgroundUploadId) ? null : backgroundUploadId.Trim(),
                BackgroundColorHex: template.BackgroundColorHex,
                ContainerPosition: NormalizeContainerPosition(template.ContainerPosition),
                PublicUpload: metadata?.PublicUpload ?? false,
                ProcessingLeaseUtc: metadata?.ProcessingLeaseUtc);

            await WriteDraftMetadataAsync(next, cancellationToken);
        }
    }

    public async Task DeleteDraftShareAsync(Guid ownerUserId, string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return;
        }

        using (await draftLocks.LockAsync(DraftLockKey(normalizedId), cancellationToken))
        {
            var metadata = await ReadDraftMetadataAsync(normalizedId, cancellationToken);
            if (metadata is null || metadata.OwnerUserId != ownerUserId)
            {
                return;
            }

            TryDeleteDirectory(GetDraftDirectory(normalizedId));
        }
    }

    private async Task<ShareTemplateData> ResolveTemplateAsync(CreateShareCommand command, CancellationToken cancellationToken)
    {
        if (command.TemplateMode == TemplateMode.PerUpload)
        {
            return new ShareTemplateData(
                string.IsNullOrWhiteSpace(command.TemplateTitle) ? "Shared file" : command.TemplateTitle.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateH1) ? "A file was shared with you" : command.TemplateH1.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateDescription) ? "Use the button below to download your file." : command.TemplateDescription.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateBackgroundImageUrl) ? null : command.TemplateBackgroundImageUrl.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateBackgroundColorHex) ? null : command.TemplateBackgroundColorHex.Trim(),
                NormalizeContainerPosition(command.TemplateContainerPosition));
        }

        var owner = OwnerOf(command);
        var template = await TemplatesOwnedBy(owner).AsNoTracking().FirstOrDefaultAsync(cancellationToken);
        if (template is null)
        {
            return new ShareTemplateData(
                $"by {owner.Email}",
                "A file was shared with you",
                string.Empty,
                null,
                null,
                "center");
        }

        return new ShareTemplateData(
            template.Title,
            template.H1,
            template.Description,
            template.BackgroundImageUrl,
            template.BackgroundColorHex,
            NormalizeContainerPosition(template.ContainerPosition));
    }

    public static string NormalizeContainerPosition(string? raw)
    {
        var value = raw?.Trim().ToLowerInvariant();
        return value switch
        {
            "center" => "center",
            "top_left" => "top_left",
            "top_right" => "top_right",
            "bottom_left" => "bottom_left",
            "bottom_right" => "bottom_right",
            "center_right" => "center_right",
            "center_left" => "center_left",
            "center_top" => "center_top",
            "center_bottom" => "center_bottom",
            _ => "center"
        };
    }

    public static string NormalizeShareExperienceType(string? raw)
    {
        return ShareModes.ToStorageValue(ShareModes.ParseExperienceType(raw));
    }

    public static string NormalizeAccessMode(string? raw)
    {
        return ShareModes.ToStorageValue(ShareModes.ParseAccessMode(raw));
    }

    public static bool AllowsZipDownload(Share share)
    {
        return ShareModes.AllowsZipDownload(ShareModes.ParseAccessMode(share.AccessMode));
    }

    public static bool AllowsPreview(Share share)
    {
        return ShareModes.AllowsPreview(ShareModes.ParseAccessMode(share.AccessMode));
    }

    private static string DetectRenderType(string fileName)
    {
        // Extension-derived only (same source as the serving policy), so a file's declared
        // content type can never promote it to an inline preview kind.
        var contentType = ContentTypePolicy.FromFileName(fileName);
        if (ContentTypePolicy.IsRasterImage(fileName))
        {
            return "image";
        }

        if (contentType.StartsWith("video/", StringComparison.Ordinal))
        {
            return "video";
        }

        if (contentType.StartsWith("audio/", StringComparison.Ordinal))
        {
            return "audio";
        }

        if (contentType == "application/pdf")
        {
            return "pdf";
        }

        var extension = (Path.GetExtension(fileName) ?? string.Empty).Trim().ToLowerInvariant();
        return extension switch
        {
            ".svg" => "svg",
            ".txt" or ".md" or ".csv" or ".json" => "text",
            ".html" or ".htm" => "html",
            ".css" => "css",
            ".js" => "js",
            _ => "binary"
        };
    }

    private string GetStagingRoot(string uploadPurpose)
    {
        return string.Equals(uploadPurpose, UploadPurposeTemplateBackground, StringComparison.Ordinal)
            ? Path.Combine(_options.StorageRoot, "uploads", "staged-template-backgrounds")
            : Path.Combine(_options.StorageRoot, "uploads", "staged");
    }

    private IEnumerable<string> GetAllStagingRoots()
    {
        yield return GetStagingRoot(UploadPurposeShareFile);
        yield return GetStagingRoot(UploadPurposeTemplateBackground);
    }

    private static string NormalizeUploadPurpose(string? uploadPurpose)
    {
        return string.Equals(uploadPurpose, UploadPurposeTemplateBackground, StringComparison.OrdinalIgnoreCase)
            ? UploadPurposeTemplateBackground
            : UploadPurposeShareFile;
    }

    private string GetDraftsRoot()
    {
        return Path.Combine(_options.StorageRoot, "uploads", "drafts");
    }

    private string GetDraftDirectory(string draftShareId)
    {
        return Path.Combine(GetDraftsRoot(), draftShareId);
    }

    private string GetDraftMetadataPath(string draftShareId)
    {
        return Path.Combine(GetDraftDirectory(draftShareId), "draft.json");
    }

    /// <summary>One marker per staged file of the draft, named by upload id and holding the declared size.</summary>
    private string GetDraftStagedIndexDirectory(string draftShareId)
    {
        return Path.Combine(GetDraftDirectory(draftShareId), "staged");
    }

    private static bool TryNormalizeDraftShareId(string? raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var text = raw.Trim();
        if (!Guid.TryParse(text, out var parsed))
        {
            return false;
        }

        normalized = parsed.ToString("N");
        return true;
    }

    private async Task<DraftShareMetadata?> ReadDraftMetadataAsync(string draftShareId, CancellationToken cancellationToken)
    {
        if (!TryNormalizeDraftShareId(draftShareId, out var normalizedId))
        {
            return null;
        }

        var metadataPath = GetDraftMetadataPath(normalizedId);
        if (!File.Exists(metadataPath))
        {
            return null;
        }

        try
        {
            var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
            return JsonSerializer.Deserialize<DraftShareMetadata>(json);
        }
        catch
        {
            return null;
        }
    }

    private async Task WriteDraftMetadataAsync(DraftShareMetadata metadata, CancellationToken cancellationToken)
    {
        var metadataPath = GetDraftMetadataPath(metadata.DraftShareId);
        Directory.CreateDirectory(Path.GetDirectoryName(metadataPath)!);
        var json = JsonSerializer.Serialize(metadata);
        await File.WriteAllTextAsync(metadataPath, json, cancellationToken);
    }

    /// <summary>
    /// Removes drafts idle for longer than their retention together with the uploads staged for them, in one locked
    /// section per draft: nothing staged into a draft revived after this section can be mistaken for stale.
    /// </summary>
    private async Task<int> CleanupStaleDraftSharesAsync(CancellationToken cancellationToken)
    {
        var draftsRoot = GetDraftsRoot();
        if (!Directory.Exists(draftsRoot))
        {
            return 0;
        }

        var removed = 0;
        foreach (var draftDirectory in Directory.EnumerateDirectories(draftsRoot))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var draftShareId = Path.GetFileName(draftDirectory);
            // Same lock as stage/refresh/finalize: activity is re-read under it, so an upload in progress or a
            // refresh that happened while this sweep was waiting keeps the draft.
            using (await draftLocks.LockAsync(DraftLockKey(draftShareId), cancellationToken))
            {
                if (!Directory.Exists(draftDirectory))
                {
                    continue;
                }

                var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
                var lastActivityUtc = metadata?.LastActivityUtc ?? Directory.GetLastWriteTimeUtc(draftDirectory);
                var retention = DraftRetention(metadata?.PublicUpload ?? false);
                var reference = lastActivityUtc;
                if (IsDraftSealed(draftShareId))
                {
                    // Submitted: judged by its processing lease (renewed by the queued job at every stage) with the
                    // longer retention, so a job that is still reading the uploads is never swept from under it.
                    retention = TimeSpan.FromTicks(Math.Max(retention.Ticks, DraftRetention(false).Ticks));
                    if (metadata?.ProcessingLeaseUtc is { } lease && lease > reference)
                    {
                        reference = lease;
                    }
                }

                if (reference > DateTime.UtcNow - retention)
                {
                    continue;
                }

                if (metadata is not null)
                {
                    removed += await DeleteStagedUploadsForDraftCoreAsync(null, draftShareId, cancellationToken);
                }

                Directory.Delete(draftDirectory, recursive: true);
                removed++;
            }
        }

        return removed;
    }

    private static string ShareTokenConflictConstraint(DbUpdateException ex) =>
        ex.InnerException is PostgresException { ConstraintName: { Length: > 0 } name } ? name : "IX_Shares_ShareToken";

    internal static bool IsShareTokenConflict(DbUpdateException ex)
    {
        var text = ex.ToString();
        if (ex.InnerException is SqlException sqlEx &&
            (sqlEx.Number == 2601 || sqlEx.Number == 2627) &&
            text.Contains("IX_Shares_ShareToken", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (ex.InnerException is PostgresException pgEx &&
            pgEx.SqlState == PostgresErrorCodes.UniqueViolation &&
            string.Equals(pgEx.ConstraintName, "IX_Shares_ShareToken", StringComparison.Ordinal))
        {
            return true;
        }

        // Text fallback also covers SQLite ("UNIQUE constraint failed"), used by the in-memory unit tests.

        return text.Contains("IX_Shares_ShareToken", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("UNIQUE constraint failed: Shares.ShareToken", StringComparison.OrdinalIgnoreCase);
    }

    private async Task DeleteShareContentFilesAsync(Share share, CancellationToken cancellationToken)
    {
        if (ObjectKey.TryNormalize(share.ZipDiskPath, out var zipKey) && zipKey.StartsWith("zips/", StringComparison.Ordinal))
        {
            await objectStore.DeleteAsync(zipKey, cancellationToken);
        }

        await contentStore.DeleteContentRootAsync(share.ContentRootPath, cancellationToken);
        await objectStore.DeletePrefixAsync($"previews/{share.Id:N}/", cancellationToken);

        // Preview .lock/.failed markers are local scratch (in S3 mode the previews themselves are not here).
        var previewMarkers = Path.Combine(_options.StorageRoot, "previews", share.Id.ToString("N"));
        if (Directory.Exists(previewMarkers))
        {
            Directory.Delete(previewMarkers, recursive: true);
        }

        var backgroundKey = ObjectKey.FromInternalMarker(share.BackgroundImageUrl);
        if (backgroundKey is null)
        {
            return;
        }

        if (!backgroundKey.StartsWith("zips/", StringComparison.Ordinal))
        {
            logger.LogInformation(
                "Skipping background deletion for non-share-owned marker {BackgroundMarker}",
                share.BackgroundImageUrl);
            return;
        }

        await objectStore.DeleteAsync(backgroundKey, cancellationToken);
    }

    private async Task<string?> CopyInternalBackgroundToShareDirectoryAsync(
        string internalMarker,
        string zipRelativePath,
        List<string> uploadedKeys,
        CancellationToken cancellationToken)
    {
        var sourceKey = ObjectKey.FromInternalMarker(internalMarker);
        if (sourceKey is null)
        {
            logger.LogWarning("Cannot copy background marker because it is not a valid internal key. Marker: {BackgroundMarker}", internalMarker);
            return null;
        }

        if (await objectStore.GetInfoAsync(sourceKey, cancellationToken) is not { } sourceInfo)
        {
            logger.LogWarning(
                "Cannot copy background marker because source object does not exist. Marker: {BackgroundMarker}",
                internalMarker);
            return null;
        }

        var backgroundKey = ShareBackgroundKey(zipRelativePath, sourceKey);
        uploadedKeys.Add(backgroundKey);
        // With the FileSystem store the copy lands on the StorageRoot volume: budget it before writing.
        using var backgroundReservation = scratchSpace.Reserve(scratchSpace.DurableDemand(sourceInfo.Length));
        await objectStore.CopyAsync(sourceKey, backgroundKey, cancellationToken);
        logger.LogInformation("Copied internal background from {SourceKey} to {TargetKey}", sourceKey, backgroundKey);
        return $"internal:{backgroundKey}";
    }
}
