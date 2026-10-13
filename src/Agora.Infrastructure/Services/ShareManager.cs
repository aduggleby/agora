using System.IO.Compression;
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
public sealed class ShareManager(
    AgoraDbContext db,
    IOptions<AgoraOptions> options,
    IShareContentStore contentStore,
    IObjectStore objectStore,
    IBackgroundJobClient backgroundJobs,
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
        IReadOnlyList<ShareArchiveFileSummary> Files);

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
        string UploaderEmail,
        string DraftShareId,
        string OriginalFileName,
        long OriginalSizeBytes,
        string ContentType,
        DateTime CreatedAtUtc,
        string? UploadPurpose);

    private sealed record DraftShareMetadata(
        string DraftShareId,
        string UploaderEmail,
        DateTime LastActivityUtc,
        string TemplateMode,
        string Title,
        string H1,
        string Description,
        string? BackgroundImageUrl,
        string? BackgroundUploadId,
        string? BackgroundColorHex,
        string? ContainerPosition);

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
        var requestedToken = command.ShareToken?.Trim();
        var hasRequestedToken = !string.IsNullOrWhiteSpace(requestedToken);
        var shareExperienceType = ShareModes.ToStorageValue(ShareModes.ParseExperienceType(command.ShareExperienceType));
        var accessMode = ShareModes.ToStorageValue(ShareModes.ParseAccessMode(command.AccessMode));

        var uploadFileNames = command.Files.Select(x => x.OriginalFileName).ToArray();
        var zipName = ArchiveNameResolver.Resolve(command.ZipFileName, uploadFileNames, now);
        var downloadPassword = string.IsNullOrWhiteSpace(command.DownloadPassword)
            ? null
            : command.DownloadPassword;
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

            for (var attempt = 0; attempt < 16; attempt += 1)
            {
                var token = hasRequestedToken
                    ? requestedToken!
                    : TokenCodec.GenerateAlphanumericToken(8);

                var share = new Share
                {
                    Id = Guid.NewGuid(),
                    UploaderEmail = EmailAddress.Normalize(command.UploaderEmail),
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
                    await db.SaveChangesAsync(cancellationToken);
                    return new CreateShareResult(share.Id, token, share.ZipDisplayName, share.ExpiresAtUtc);
                }
                catch (DbUpdateException ex) when (IsShareTokenConflict(ex))
                {
                    logger.LogWarning(
                        ex,
                        "Share token conflict while creating share. token={Token} uploader={Uploader} requestedToken={RequestedToken} hasRequestedToken={HasRequestedToken} provider={Provider}",
                        token,
                        command.UploaderEmail,
                        requestedToken ?? "<none>",
                        hasRequestedToken,
                        db.Database.ProviderName ?? "<unknown>");
                    db.Entry(share).State = EntityState.Detached;
                    if (hasRequestedToken)
                    {
                        throw new InvalidOperationException("Share token is already in use.", ex);
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

    public Task<Share?> FindByTokenAsync(string token, CancellationToken cancellationToken)
    {
        return db.Shares
            .Include(x => x.Files)
            .Include(x => x.DownloadEvents)
            .SingleOrDefaultAsync(x => x.ShareToken == token, cancellationToken);
    }

    public Task<Share?> FindByTokenForUploaderAsync(string token, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        return db.Shares
            .SingleOrDefaultAsync(x => x.ShareToken == token && x.UploaderEmail == normalizedEmail, cancellationToken);
    }

    public Task<List<UserShareSummary>> ListRecentSharesForUploaderAsync(string uploaderEmail, int take, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        return db.Shares
            .AsNoTracking()
            .Where(x => x.UploaderEmail == normalizedEmail && x.DeletedAtUtc == null)
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
                x.Files
                    .Select(file => new ShareArchiveFileSummary(
                        file.OriginalFilename,
                        file.OriginalSizeBytes))
                    .ToList()))
            .ToListAsync(cancellationToken);
    }

    public async Task<bool> DeleteShareAsync(Guid shareId, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        var share = await db.Shares.SingleOrDefaultAsync(x => x.Id == shareId && x.UploaderEmail == normalizedEmail, cancellationToken);
        if (share is null)
        {
            return false;
        }

        if (share.DeletedAtUtc is null)
        {
            share.DeletedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(cancellationToken);
        }

        backgroundJobs.Enqueue<ShareManager>(x => x.DeleteShareFilesAsync(shareId, CancellationToken.None));
        return true;
    }

    public async Task<bool> ReenableShareFor24HoursAsync(Guid shareId, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        var share = await db.Shares.SingleOrDefaultAsync(
            x => x.Id == shareId && x.UploaderEmail == normalizedEmail && x.DeletedAtUtc == null,
            cancellationToken);
        if (share is null)
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

    public async Task<string?> GetCopyableShareTokenAsync(Guid shareId, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        var share = await db.Shares.SingleOrDefaultAsync(
            x => x.Id == shareId && x.UploaderEmail == normalizedEmail && x.DeletedAtUtc == null,
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
        return !await db.Shares.AsNoTracking().AnyAsync(x => x.ShareToken == token, cancellationToken);
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

    public static bool IsExpired(Share share, DateTime utcNow)
    {
        if (share.DeletedAtUtc is not null)
        {
            return true;
        }

        return share.ExpiresAtUtc is not null && utcNow >= share.ExpiresAtUtc.Value;
    }

    public async Task RecordDownloadAsync(Share share, string token, string ipAddress, string userAgent, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var metadata = BrowserMetadataParser.ToJson(userAgent);
        var mode = (share.NotifyMode ?? "none").Trim().ToLowerInvariant();

        var shouldSend = false;

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
            shouldSend = true;
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
    }

    public async Task UpsertAccountTemplateAsync(string uploaderEmail, ShareTemplateData template, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        var existing = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == normalizedEmail, cancellationToken);
        if (existing is null)
        {
            db.AccountTemplates.Add(new AccountTemplate
            {
                Id = Guid.NewGuid(),
                UploaderEmail = normalizedEmail,
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
    }

    public async Task<ShareTemplateData> GetAccountTemplateAsync(string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = EmailAddress.Normalize(uploaderEmail);
        var existing = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == normalizedEmail, cancellationToken);
        if (existing is null)
        {
            return new ShareTemplateData(
                $"by {normalizedEmail}",
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
        var purgeCutoff = now.AddDays(-7);
        var expired = await db.Shares
            .Where(x => x.DeletedAtUtc == null && x.ExpiresAtUtc != null && x.ExpiresAtUtc <= purgeCutoff)
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
        string uploaderEmail,
        string draftShareId,
        string originalFileName,
        long originalSizeBytes,
        Stream source,
        CancellationToken cancellationToken,
        string uploadPurpose = UploadPurposeShareFile)
    {
        var normalizedPurpose = NormalizeUploadPurpose(uploadPurpose);
        var uploadId = Guid.NewGuid().ToString("N");
        var stagingDirectory = Path.Combine(GetStagingRoot(normalizedPurpose), uploadId);
        Directory.CreateDirectory(stagingDirectory);

        var sanitizedName = ArchiveNameResolver.Sanitize(originalFileName);
        var payloadPath = Path.Combine(stagingDirectory, "payload.bin");
        var metadataPath = Path.Combine(stagingDirectory, "metadata.json");

        await using (var destination = File.Create(payloadPath))
        {
            await source.CopyToAsync(destination, cancellationToken);
        }

        var metadata = new StagedUploadMetadata(
            UploadId: uploadId,
            UploaderEmail: uploaderEmail.Trim(),
            DraftShareId: draftShareId,
            OriginalFileName: sanitizedName,
            OriginalSizeBytes: originalSizeBytes,
            // Derived from the extension only; the multipart Content-Type the client sent is never trusted.
            ContentType: ContentTypePolicy.FromFileName(sanitizedName),
            CreatedAtUtc: DateTime.UtcNow,
            UploadPurpose: normalizedPurpose);

        await File.WriteAllTextAsync(metadataPath, JsonSerializer.Serialize(metadata), cancellationToken);

        return new StagedUploadFile(
            UploadId: uploadId,
            OriginalFileName: metadata.OriginalFileName,
            OriginalSizeBytes: metadata.OriginalSizeBytes,
            ContentType: metadata.ContentType,
            TempPath: payloadPath,
            DirectoryPath: stagingDirectory);
    }

    public async Task<IReadOnlyList<StagedUploadFile>> ResolveStagedUploadsAsync(
        string uploaderEmail,
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
        var normalizedUploader = uploaderEmail.Trim();
        var normalizedPurpose = NormalizeUploadPurpose(requiredPurpose);

        foreach (var rawId in uploadIds)
        {
            var uploadId = (rawId ?? string.Empty).Trim();
            if (uploadId.Length == 0)
            {
                continue;
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

            if (!string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
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
        string uploaderEmail,
        string draftShareId,
        CancellationToken cancellationToken)
    {
        var stagingRoot = GetStagingRoot(UploadPurposeShareFile);
        if (!Directory.Exists(stagingRoot))
        {
            return [];
        }

        var normalizedUploader = uploaderEmail.Trim();
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

            if (!string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
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
        string uploaderEmail,
        string draftShareId,
        string uploadId,
        CancellationToken cancellationToken)
    {
        var normalizedUploader = uploaderEmail.Trim();
        var normalizedUploadId = (uploadId ?? string.Empty).Trim();
        if (normalizedUploadId.Length == 0)
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

        if (metadata is null)
        {
            return false;
        }

        if (!string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(metadata.DraftShareId, draftShareId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        Directory.Delete(stagingDirectory, recursive: true);
        return true;
    }

    public async Task<int> DeleteStagedUploadsForDraftAsync(
        string uploaderEmail,
        string draftShareId,
        CancellationToken cancellationToken)
    {
        var normalizedUploader = uploaderEmail.Trim();
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

                if (!string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
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
        var staleDraftIds = await CleanupStaleDraftSharesAsync(cancellationToken);
        var cutoff = DateTime.UtcNow.AddHours(-Math.Abs(_options.ZombieUploadRetentionHours));
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
                var payloadPath = Path.Combine(stagingDirectory, "payload.bin");
                var createdAtUtc = Directory.GetCreationTimeUtc(stagingDirectory);

                if (File.Exists(metadataPath))
                {
                    try
                    {
                        var json = await File.ReadAllTextAsync(metadataPath, cancellationToken);
                        var metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
                        if (metadata is not null)
                        {
                            createdAtUtc = metadata.CreatedAtUtc;
                        }
                    }
                    catch
                    {
                        // Keep fallback timestamp when metadata cannot be parsed.
                    }
                }

                var isInvalid = !File.Exists(metadataPath) || !File.Exists(payloadPath);
                var isStaleDraftUpload = metadataPath is not null && IsUploadForStaleDraft(metadataPath, staleDraftIds, cancellationToken);
                if (isInvalid || isStaleDraftUpload || createdAtUtc <= cutoff)
                {
                    Directory.Delete(stagingDirectory, recursive: true);
                    removed++;
                }
            }
        }

        return removed + staleDraftIds.Count + SweepStaleScratchFiles(cutoff, cancellationToken);
    }

    /// <summary>
    /// Deletes scratch files (under tmp/, including ASP.NET's tmp/aspnet buffers) and preview .lock markers older than
    /// the cutoff. Only files are removed, so in-use directories such as tmp/aspnet survive.
    /// </summary>
    private int SweepStaleScratchFiles(DateTime cutoffUtc, CancellationToken cancellationToken)
    {
        var candidates = new[]
        {
            (Root: ScratchFiles.Root(_options.StorageRoot), Pattern: "*"),
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

    public async Task<string> EnsureDraftShareAsync(string uploaderEmail, string? requestedDraftShareId, CancellationToken cancellationToken)
    {
        var normalizedUploader = uploaderEmail.Trim();
        var draftShareId = TryNormalizeDraftShareId(requestedDraftShareId, out var normalizedId)
            ? normalizedId
            : Guid.NewGuid().ToString("N");
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is not null && !string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Draft share does not belong to the current user.");
        }

        var now = DateTime.UtcNow;
        var next = metadata is null
            ? new DraftShareMetadata(
                DraftShareId: draftShareId,
                UploaderEmail: normalizedUploader,
                LastActivityUtc: now,
                TemplateMode: "account_default",
                Title: string.Empty,
                H1: string.Empty,
                Description: string.Empty,
                BackgroundImageUrl: null,
                BackgroundUploadId: null,
                BackgroundColorHex: null,
                ContainerPosition: "center")
            : metadata with { LastActivityUtc = now };

        await WriteDraftMetadataAsync(next, cancellationToken);
        return draftShareId;
    }

    public async Task<DraftTemplateState> GetDraftTemplateAsync(string uploaderEmail, string draftShareId, CancellationToken cancellationToken)
    {
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is null || !string.Equals(metadata.UploaderEmail, uploaderEmail.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return new DraftTemplateState(draftShareId, "account_default", string.Empty, string.Empty, string.Empty, null, null, null, "center");
        }

        var updated = metadata with { LastActivityUtc = DateTime.UtcNow };
        await WriteDraftMetadataAsync(updated, cancellationToken);
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
        string uploaderEmail,
        string draftShareId,
        string templateMode,
        ShareTemplateData template,
        string? backgroundUploadId,
        CancellationToken cancellationToken)
    {
        var normalizedUploader = uploaderEmail.Trim();
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is not null && !string.Equals(metadata.UploaderEmail, normalizedUploader, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Draft share does not belong to the current user.");
        }

        var next = new DraftShareMetadata(
            DraftShareId: draftShareId,
            UploaderEmail: normalizedUploader,
            LastActivityUtc: DateTime.UtcNow,
            TemplateMode: string.Equals(templateMode, "per_upload", StringComparison.OrdinalIgnoreCase) ? "per_upload" : "account_default",
            Title: template.Title,
            H1: template.H1,
            Description: template.Description,
            BackgroundImageUrl: template.BackgroundImageUrl,
            BackgroundUploadId: string.IsNullOrWhiteSpace(backgroundUploadId) ? null : backgroundUploadId.Trim(),
            BackgroundColorHex: template.BackgroundColorHex,
            ContainerPosition: NormalizeContainerPosition(template.ContainerPosition));

        await WriteDraftMetadataAsync(next, cancellationToken);
    }

    public async Task DeleteDraftShareAsync(string uploaderEmail, string draftShareId, CancellationToken cancellationToken)
    {
        var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
        if (metadata is null || !string.Equals(metadata.UploaderEmail, uploaderEmail.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var draftDirectory = GetDraftDirectory(draftShareId);
        if (Directory.Exists(draftDirectory))
        {
            Directory.Delete(draftDirectory, recursive: true);
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

        var template = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == EmailAddress.Normalize(command.UploaderEmail), cancellationToken);
        if (template is null)
        {
            return new ShareTemplateData(
                $"by {command.UploaderEmail.Trim()}",
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

    private async Task<HashSet<string>> CleanupStaleDraftSharesAsync(CancellationToken cancellationToken)
    {
        var draftsRoot = GetDraftsRoot();
        if (!Directory.Exists(draftsRoot))
        {
            return [];
        }

        var staleCutoff = DateTime.UtcNow.AddHours(-24);
        var removedDraftIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var draftDirectory in Directory.EnumerateDirectories(draftsRoot))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var draftShareId = Path.GetFileName(draftDirectory);
            var metadata = await ReadDraftMetadataAsync(draftShareId, cancellationToken);
            var lastActivityUtc = metadata?.LastActivityUtc ?? Directory.GetLastWriteTimeUtc(draftDirectory);
            if (lastActivityUtc <= staleCutoff)
            {
                removedDraftIds.Add(draftShareId);
                Directory.Delete(draftDirectory, recursive: true);
            }
        }

        return removedDraftIds;
    }

    private bool IsUploadForStaleDraft(string metadataPath, HashSet<string> staleDraftIds, CancellationToken cancellationToken)
    {
        if (staleDraftIds.Count == 0)
        {
            return false;
        }

        try
        {
            var json = File.ReadAllText(metadataPath);
            var metadata = JsonSerializer.Deserialize<StagedUploadMetadata>(json);
            if (metadata is null)
            {
                return false;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return staleDraftIds.Contains(metadata.DraftShareId);
        }
        catch
        {
            return false;
        }
    }

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

        if (await objectStore.GetInfoAsync(sourceKey, cancellationToken) is null)
        {
            logger.LogWarning(
                "Cannot copy background marker because source object does not exist. Marker: {BackgroundMarker}",
                internalMarker);
            return null;
        }

        var backgroundKey = ShareBackgroundKey(zipRelativePath, sourceKey);
        uploadedKeys.Add(backgroundKey);
        await objectStore.CopyAsync(sourceKey, backgroundKey, cancellationToken);
        logger.LogInformation("Copied internal background from {SourceKey} to {TargetKey}", sourceKey, backgroundKey);
        return $"internal:{backgroundKey}";
    }
}
