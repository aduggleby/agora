using System.IO.Compression;
using System.Text.Json;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace Agora.Infrastructure.Services;

public sealed class ShareManager(
    AgoraDbContext db,
    IOptions<AgoraOptions> options,
    IShareContentStore contentStore,
    IBackgroundJobClient backgroundJobs,
    ILogger<ShareManager> logger)
{
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
        DateTime CreatedAtUtc);

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
        var persistedContent = await contentStore.PersistShareFilesAsync(command.Files, now, cancellationToken);
        var shareContentRelativePath = persistedContent.ContentRootPath;
        var storedFiles = persistedContent.Files;

        var zipRelativePath = Path.Combine("zips", now.ToString("yyyy"), now.ToString("MM"), $"{Guid.NewGuid()}.zip");
        var zipAbsolutePath = Path.Combine(_options.StorageRoot, zipRelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(zipAbsolutePath)!);

        await using (var outStream = File.Create(zipAbsolutePath))
        await using (var zip = new ZipArchive(outStream, ZipArchiveMode.Create))
        {
            foreach (var file in storedFiles)
            {
                var entry = zip.CreateEntry(file.EntryName, CompressionLevel.Fastest);
                await using var entryStream = entry.Open();
                await using var source = File.OpenRead(file.StoredAbsolutePath);
                await source.CopyToAsync(entryStream, cancellationToken);
            }
        }

        var zipInfo = new FileInfo(zipAbsolutePath);
        var archiveDiskPath = zipRelativePath;
        if (downloadPassword is not null)
        {
            var encryptedRelativePath = Path.Combine("zips", now.ToString("yyyy"), now.ToString("MM"), $"{Guid.NewGuid()}.agz");
            var encryptedAbsolutePath = Path.Combine(_options.StorageRoot, encryptedRelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(encryptedAbsolutePath)!);
            await ZipEncryption.EncryptFileAsync(zipAbsolutePath, encryptedAbsolutePath, downloadPassword, cancellationToken);
            File.Delete(zipAbsolutePath);
            archiveDiskPath = encryptedRelativePath;
        }

        var template = await ResolveTemplateAsync(command, cancellationToken);
        logger.LogInformation(
            "Resolved download page template for uploader {UploaderEmail} mode {TemplateMode} with background marker {BackgroundMarker}",
            command.UploaderEmail,
            command.TemplateMode,
            template.BackgroundImageUrl ?? "<none>");

        if (command.TemplateMode == TemplateMode.PerUpload && command.TemplateBackgroundFile is not null)
        {
            var backgroundMarker = CopyTemplateBackgroundToShareDirectory(command.TemplateBackgroundFile, zipRelativePath);
            template = template with { BackgroundImageUrl = backgroundMarker };
            logger.LogInformation(
                "Copied per-share custom background for uploader {UploaderEmail} to marker {BackgroundMarker}",
                command.UploaderEmail,
                backgroundMarker ?? "<none>");
        }
        else if (command.TemplateMode == TemplateMode.AccountDefault &&
                 !string.IsNullOrWhiteSpace(template.BackgroundImageUrl) &&
                 template.BackgroundImageUrl.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
        {
            var sourceMarker = template.BackgroundImageUrl;
            var copiedMarker = CopyInternalBackgroundToShareDirectory(template.BackgroundImageUrl, zipRelativePath);
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
            var tokenHash = TokenCodec.HashToken(token);
            var tokenPrefix = TokenCodec.TokenPrefix(token);

            var share = new Share
            {
                Id = Guid.NewGuid(),
                UploaderEmail = command.UploaderEmail.Trim(),
                ShareToken = token,
                ShareTokenHash = tokenHash,
                ShareTokenPrefix = tokenPrefix,
                ZipDisplayName = zipName,
                ZipDiskPath = archiveDiskPath,
                ZipSizeBytes = zipInfo.Length,
                ShareExperienceType = shareExperienceType,
                AccessMode = accessMode,
                ContentRootPath = shareContentRelativePath,
                DownloadPasswordHash = downloadPassword is null ? null : PasswordHasher.Hash(downloadPassword),
                UploaderMessage = command.Message,
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
                    RenderType = DetectRenderType(x.EntryName, x.ContentType),
                    OriginalSizeBytes = x.SizeBytes,
                    DetectedContentType = x.ContentType
                }).ToList()
            };

            db.Shares.Add(share);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                return new CreateShareResult(share.Id, token, share.ZipDisplayName, share.ExpiresAtUtc);
            }
            catch (DbUpdateException ex) when (IsShareTokenConflict(ex))
            {
                db.Entry(share).State = EntityState.Detached;
                if (hasRequestedToken)
                {
                    throw new InvalidOperationException("Share token is already in use.", ex);
                }
            }
        }

        throw new InvalidOperationException("Unable to generate a unique share token right now.");
    }

    public Task<Share?> FindByTokenAsync(string token, CancellationToken cancellationToken)
    {
        var hash = TokenCodec.HashToken(token);
        return db.Shares
            .Include(x => x.Files)
            .Include(x => x.DownloadEvents)
            .SingleOrDefaultAsync(x => x.ShareTokenHash == hash, cancellationToken);
    }

    public Task<Share?> FindByTokenForUploaderAsync(string token, string uploaderEmail, CancellationToken cancellationToken)
    {
        var hash = TokenCodec.HashToken(token);
        var normalizedEmail = uploaderEmail.Trim();
        return db.Shares
            .SingleOrDefaultAsync(x => x.ShareTokenHash == hash && x.UploaderEmail == normalizedEmail, cancellationToken);
    }

    public Task<List<UserShareSummary>> ListRecentSharesForUploaderAsync(string uploaderEmail, int take, CancellationToken cancellationToken)
    {
        var normalizedEmail = uploaderEmail.Trim();
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
                x.Files
                    .Select(file => new ShareArchiveFileSummary(
                        file.OriginalFilename,
                        file.OriginalSizeBytes))
                    .ToList()))
            .ToListAsync(cancellationToken);
    }

    public async Task<bool> DeleteShareAsync(Guid shareId, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = uploaderEmail.Trim();
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
        var normalizedEmail = uploaderEmail.Trim();
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

        var zipAbsolutePath = Path.Combine(_options.StorageRoot, share.ZipDiskPath);
        if (!File.Exists(zipAbsolutePath))
        {
            return false;
        }

        share.ExpiresAtUtc = now.AddHours(24);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<string?> GetCopyableShareTokenAsync(Guid shareId, string uploaderEmail, CancellationToken cancellationToken)
    {
        var normalizedEmail = uploaderEmail.Trim();
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

        // Backfill legacy rows that predate recoverable token storage.
        var generated = await GenerateUniqueShareTokenAsync(8, cancellationToken);
        share.ShareToken = generated;
        share.ShareTokenHash = TokenCodec.HashToken(generated);
        share.ShareTokenPrefix = TokenCodec.TokenPrefix(generated);
        await db.SaveChangesAsync(cancellationToken);
        return generated;
    }

    public async Task<bool> IsShareTokenAvailableAsync(string token, CancellationToken cancellationToken)
    {
        var hash = TokenCodec.HashToken(token);
        return !await db.Shares.AsNoTracking().AnyAsync(x => x.ShareTokenHash == hash, cancellationToken);
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

    public async Task DeleteShareFilesAsync(Guid shareId, CancellationToken cancellationToken)
    {
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(x => x.Id == shareId, cancellationToken);
        if (share is null)
        {
            return;
        }

        DeleteShareContentFiles(share.ZipDiskPath, share.BackgroundImageUrl, share.ContentRootPath);
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
            var affected = await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE Shares SET FirstDownloadedAtUtc = {now} WHERE Id = {share.Id} AND FirstDownloadedAtUtc IS NULL", cancellationToken);
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
                x.ProcessDownloadEventAsync(downloadEvent.Id, token, CancellationToken.None));
        }
    }

    public async Task UpsertAccountTemplateAsync(string uploaderEmail, ShareTemplateData template, CancellationToken cancellationToken)
    {
        var normalizedEmail = uploaderEmail.Trim();
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
        var normalizedEmail = uploaderEmail.Trim();
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
            DeleteShareContentFiles(share.ZipDiskPath, share.BackgroundImageUrl, share.ContentRootPath);
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
        string contentType,
        Stream source,
        CancellationToken cancellationToken)
    {
        var uploadId = Guid.NewGuid().ToString("N");
        var stagingDirectory = Path.Combine(GetStagingRoot(), uploadId);
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
            ContentType: string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
            CreatedAtUtc: DateTime.UtcNow);

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
        CancellationToken cancellationToken)
    {
        if (uploadIds.Count == 0)
        {
            return [];
        }

        var resolved = new List<StagedUploadFile>(uploadIds.Count);
        var normalizedUploader = uploaderEmail.Trim();

        foreach (var rawId in uploadIds)
        {
            var uploadId = (rawId ?? string.Empty).Trim();
            if (uploadId.Length == 0)
            {
                continue;
            }

            var stagingDirectory = Path.Combine(GetStagingRoot(), uploadId);
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
        var stagingRoot = GetStagingRoot();
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

        var stagingDirectory = Path.Combine(GetStagingRoot(), normalizedUploadId);
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

    public async Task<int> CleanupZombieUploadsAsync(CancellationToken cancellationToken)
    {
        var staleDraftIds = await CleanupStaleDraftSharesAsync(cancellationToken);
        var stagingRoot = GetStagingRoot();
        if (!Directory.Exists(stagingRoot))
        {
            return staleDraftIds.Count;
        }

        var cutoff = DateTime.UtcNow.AddHours(-Math.Abs(_options.ZombieUploadRetentionHours));
        var removed = 0;

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

        return removed + staleDraftIds.Count;
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

        var template = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == command.UploaderEmail.Trim(), cancellationToken);
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

    private static string DetectRenderType(string fileName, string contentType)
    {
        var normalizedContentType = (contentType ?? string.Empty).Trim().ToLowerInvariant();
        var extension = (Path.GetExtension(fileName) ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedContentType.StartsWith("image/", StringComparison.Ordinal))
        {
            return "image";
        }

        if (normalizedContentType.StartsWith("video/", StringComparison.Ordinal))
        {
            return "video";
        }

        if (normalizedContentType.StartsWith("audio/", StringComparison.Ordinal))
        {
            return "audio";
        }

        if (normalizedContentType.Contains("pdf", StringComparison.Ordinal))
        {
            return "pdf";
        }

        return extension switch
        {
            ".jpg" or ".jpeg" or ".png" or ".gif" or ".webp" or ".bmp" => "image",
            ".svg" => "svg",
            ".pdf" => "pdf",
            ".mp4" or ".webm" or ".mov" => "video",
            ".mp3" or ".wav" or ".ogg" => "audio",
            ".txt" or ".md" or ".csv" or ".json" => "text",
            ".html" or ".htm" => "html",
            ".css" => "css",
            ".js" => "js",
            _ => "binary"
        };
    }

    private string GetStagingRoot()
    {
        return Path.Combine(_options.StorageRoot, "uploads", "staged");
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

    private static bool IsShareTokenConflict(DbUpdateException ex)
    {
        var text = ex.ToString();
        return text.Contains("ShareTokenHash", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("IX_Shares_ShareTokenHash", StringComparison.OrdinalIgnoreCase);
    }

    private string CopyTemplateBackgroundToShareDirectory(UploadSourceFile backgroundFile, string zipRelativePath)
    {
        var zipDirectory = Path.GetDirectoryName(zipRelativePath) ?? "zips";
        var zipStem = Path.GetFileNameWithoutExtension(zipRelativePath);
        var safeExtension = Path.GetExtension(backgroundFile.OriginalFileName);
        if (string.IsNullOrWhiteSpace(safeExtension))
        {
            safeExtension = ".bin";
        }

        var backgroundRelativePath = Path.Combine(zipDirectory, $"{zipStem}-background{safeExtension}");
        var backgroundAbsolutePath = Path.Combine(_options.StorageRoot, backgroundRelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(backgroundAbsolutePath)!);
        File.Copy(backgroundFile.TempPath, backgroundAbsolutePath, overwrite: true);
        return $"internal:{backgroundRelativePath.Replace('\\', '/')}";
    }

    private void DeleteShareContentFiles(string zipDiskPath, string? backgroundImageMarker, string? contentRootPath)
    {
        var zipAbsolutePath = Path.Combine(_options.StorageRoot, zipDiskPath);
        if (File.Exists(zipAbsolutePath))
        {
            File.Delete(zipAbsolutePath);
        }

        contentStore.DeleteContentRoot(contentRootPath);

        var marker = backgroundImageMarker ?? string.Empty;
        if (!marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
        if (relativePath.Length == 0)
        {
            return;
        }

        var normalizedRelativePath = relativePath.Replace('\\', '/');
        if (!normalizedRelativePath.StartsWith("zips/", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation(
                "Skipping background deletion for non-share-owned marker {BackgroundMarker}",
                backgroundImageMarker ?? "<none>");
            return;
        }

        var backgroundAbsolutePath = Path.Combine(_options.StorageRoot, relativePath);
        if (File.Exists(backgroundAbsolutePath))
        {
            File.Delete(backgroundAbsolutePath);
        }
    }

    private string? CopyInternalBackgroundToShareDirectory(string internalMarker, string zipRelativePath)
    {
        var marker = internalMarker ?? string.Empty;
        if (!marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Cannot copy background marker because it is not internal. Marker: {BackgroundMarker}",
                internalMarker ?? "<none>");
            return null;
        }

        var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
        if (relativePath.Length == 0)
        {
            logger.LogWarning("Cannot copy background marker because relative path was empty. Marker: {BackgroundMarker}", marker);
            return null;
        }

        var storageRoot = Path.GetFullPath(_options.StorageRoot);
        var sourceAbsolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
        if (!sourceAbsolutePath.StartsWith(storageRoot, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Cannot copy background marker because source path escaped storage root. Marker: {BackgroundMarker}",
                marker);
            return null;
        }

        if (!File.Exists(sourceAbsolutePath))
        {
            logger.LogWarning(
                "Cannot copy background marker because source file does not exist. Marker: {BackgroundMarker} SourcePath: {SourcePath}",
                marker,
                sourceAbsolutePath);
            return null;
        }

        var zipDirectory = Path.GetDirectoryName(zipRelativePath) ?? "zips";
        var zipStem = Path.GetFileNameWithoutExtension(zipRelativePath);
        var safeExtension = Path.GetExtension(relativePath);
        if (string.IsNullOrWhiteSpace(safeExtension))
        {
            safeExtension = ".bin";
        }

        var backgroundRelativePath = Path.Combine(zipDirectory, $"{zipStem}-background{safeExtension}");
        var backgroundAbsolutePath = Path.Combine(storageRoot, backgroundRelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(backgroundAbsolutePath)!);
        File.Copy(sourceAbsolutePath, backgroundAbsolutePath, overwrite: true);
        logger.LogInformation(
            "Copied internal background from {SourcePath} to {TargetPath}",
            sourceAbsolutePath,
            backgroundAbsolutePath);
        return $"internal:{backgroundRelativePath.Replace('\\', '/')}";
    }
}
