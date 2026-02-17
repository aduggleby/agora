using System.IO.Compression;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Agora.Infrastructure.Services;

public sealed class ShareManager(
    AgoraDbContext db,
    IOptions<AgoraOptions> options,
    IBackgroundJobClient backgroundJobs)
{
    private readonly AgoraOptions _options = options.Value;

    public async Task<CreateShareResult> CreateShareAsync(CreateShareCommand command, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var token = TokenCodec.GenerateToken();
        var tokenHash = TokenCodec.HashToken(token);
        var tokenPrefix = TokenCodec.TokenPrefix(token);

        var uploadFileNames = command.Files.Select(x => x.OriginalFileName).ToArray();
        var zipName = ArchiveNameResolver.Resolve(command.ZipFileName, uploadFileNames, now);

        var zipRelativePath = Path.Combine("zips", now.ToString("yyyy"), now.ToString("MM"), $"{Guid.NewGuid()}.zip");
        var zipAbsolutePath = Path.Combine(_options.StorageRoot, zipRelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(zipAbsolutePath)!);

        await using (var outStream = File.Create(zipAbsolutePath))
        await using (var zip = new ZipArchive(outStream, ZipArchiveMode.Create))
        {
            foreach (var file in command.Files)
            {
                var entryName = ArchiveNameResolver.Sanitize(file.OriginalFileName);
                var entry = zip.CreateEntry(entryName, CompressionLevel.Fastest);
                await using var entryStream = entry.Open();
                await using var source = File.OpenRead(file.TempPath);
                await source.CopyToAsync(entryStream, cancellationToken);
            }
        }

        var zipInfo = new FileInfo(zipAbsolutePath);

        var template = await ResolveTemplateAsync(command, cancellationToken);

        var share = new Share
        {
            Id = Guid.NewGuid(),
            UploaderEmail = command.UploaderEmail.Trim(),
            ShareTokenHash = tokenHash,
            ShareTokenPrefix = tokenPrefix,
            ZipDisplayName = zipName,
            ZipDiskPath = zipRelativePath,
            ZipSizeBytes = zipInfo.Length,
            UploaderMessage = command.Message,
            NotifyMode = command.NotifyMode,
            ExpiresAtUtc = command.ExpiryMode == ExpiryMode.Indefinite ? null : command.ExpiresAtUtc,
            CreatedAtUtc = now,
            PageTitle = template.Title,
            PageH1 = template.H1,
            PageDescription = template.Description,
            BackgroundImageUrl = template.BackgroundImageUrl,
            Files = command.Files.Select(x => new ShareFile
            {
                Id = Guid.NewGuid(),
                OriginalFilename = x.OriginalFileName,
                OriginalSizeBytes = x.OriginalSizeBytes,
                DetectedContentType = x.ContentType
            }).ToList()
        };

        db.Shares.Add(share);
        await db.SaveChangesAsync(cancellationToken);

        return new CreateShareResult(share.Id, token, share.ZipDisplayName, share.ExpiresAtUtc);
    }

    public Task<Share?> FindByTokenAsync(string token, CancellationToken cancellationToken)
    {
        var hash = TokenCodec.HashToken(token);
        return db.Shares
            .Include(x => x.Files)
            .Include(x => x.DownloadEvents)
            .SingleOrDefaultAsync(x => x.ShareTokenHash == hash, cancellationToken);
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
                UpdatedAtUtc = DateTime.UtcNow
            });
        }
        else
        {
            existing.Title = template.Title;
            existing.H1 = template.H1;
            existing.Description = template.Description;
            existing.BackgroundImageUrl = template.BackgroundImageUrl;
            existing.UpdatedAtUtc = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<int> CleanupExpiredSharesAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var expired = await db.Shares
            .Where(x => x.DeletedAtUtc == null && x.ExpiresAtUtc != null && x.ExpiresAtUtc <= now)
            .ToListAsync(cancellationToken);

        var count = 0;
        foreach (var share in expired)
        {
            var absolutePath = Path.Combine(_options.StorageRoot, share.ZipDiskPath);
            if (File.Exists(absolutePath))
            {
                File.Delete(absolutePath);
            }

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

    private async Task<ShareTemplateData> ResolveTemplateAsync(CreateShareCommand command, CancellationToken cancellationToken)
    {
        if (command.TemplateMode == TemplateMode.PerUpload)
        {
            return new ShareTemplateData(
                string.IsNullOrWhiteSpace(command.TemplateTitle) ? "Shared file" : command.TemplateTitle.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateH1) ? "A file was shared with you" : command.TemplateH1.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateDescription) ? "Use the button below to download your file." : command.TemplateDescription.Trim(),
                string.IsNullOrWhiteSpace(command.TemplateBackgroundImageUrl) ? null : command.TemplateBackgroundImageUrl.Trim());
        }

        var template = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == command.UploaderEmail.Trim(), cancellationToken);
        if (template is null)
        {
            return new ShareTemplateData("Shared file", "A file was shared with you", "Use the button below to download your file.", null);
        }

        return new ShareTemplateData(template.Title, template.H1, template.Description, template.BackgroundImageUrl);
    }
}
