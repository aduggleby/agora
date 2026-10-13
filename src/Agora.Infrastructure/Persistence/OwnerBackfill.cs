using System.Globalization;
using Agora.Application.Constants;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace Agora.Infrastructure.Persistence;

/// <summary>
/// One-time startup step that stamps <c>OwnerUserId</c> on shares and account templates created before owners were
/// tracked: every row whose owner is still null and whose uploader address matches a user (compared lower-case)
/// gets that user's id. It runs until a <see cref="SystemSettingKeys.OwnershipBackfillCompletedAt"/> row records
/// its completion and never again after that; rows still without an owner then stay unreachable (quarantined),
/// and later starts only count them.
/// </summary>
public static class OwnerBackfill
{
    public sealed record Result(bool Skipped, int Shares, int Templates, int QuarantinedShares, int QuarantinedTemplates);

    public static async Task<Result> RunAsync(AgoraDbContext db, CancellationToken cancellationToken)
    {
        var completed = await db.SystemSettings.AnyAsync(x => x.Key == SystemSettingKeys.OwnershipBackfillCompletedAt, cancellationToken);
        if (completed)
        {
            return new Result(
                Skipped: true,
                Shares: 0,
                Templates: 0,
                QuarantinedShares: await db.Shares.CountAsync(x => x.OwnerUserId == null, cancellationToken),
                QuarantinedTemplates: await db.AccountTemplates.CountAsync(x => x.OwnerUserId == null, cancellationToken));
        }

        var shareEmails = await db.Shares
            .Where(x => x.OwnerUserId == null)
            .Select(x => x.UploaderEmail)
            .Distinct()
            .ToListAsync(cancellationToken);
        var templateEmails = await db.AccountTemplates
            .Where(x => x.OwnerUserId == null)
            .Select(x => x.UploaderEmail)
            .Distinct()
            .ToListAsync(cancellationToken);

        var users = await db.Users
            .Select(x => new { x.Id, x.Email })
            .ToListAsync(cancellationToken);
        var byEmail = new Dictionary<string, Guid>(StringComparer.Ordinal);
        foreach (var user in users)
        {
            byEmail.TryAdd(EmailAddress.Normalize(user.Email), user.Id);
        }

        var shares = 0;
        foreach (var (email, userId) in MatchingUsers(shareEmails, byEmail))
        {
            shares += await db.Shares
                .Where(x => x.OwnerUserId == null && x.UploaderEmail.ToLower() == email)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.OwnerUserId, userId), cancellationToken);
        }

        var templates = 0;
        foreach (var (email, userId) in MatchingUsers(templateEmails, byEmail))
        {
            templates += await db.AccountTemplates
                .Where(x => x.OwnerUserId == null && x.UploaderEmail.ToLower() == email)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.OwnerUserId, userId), cancellationToken);
        }

        db.SystemSettings.Add(new SystemSetting
        {
            Key = SystemSettingKeys.OwnershipBackfillCompletedAt,
            Value = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync(cancellationToken);

        return new Result(
            Skipped: false,
            Shares: shares,
            Templates: templates,
            QuarantinedShares: await db.Shares.CountAsync(x => x.OwnerUserId == null, cancellationToken),
            QuarantinedTemplates: await db.AccountTemplates.CountAsync(x => x.OwnerUserId == null, cancellationToken));
    }

    private static IEnumerable<(string Email, Guid UserId)> MatchingUsers(IEnumerable<string> uploaderEmails, Dictionary<string, Guid> byEmail)
    {
        var seen = new HashSet<Guid>();
        foreach (var raw in uploaderEmails)
        {
            var email = EmailAddress.Normalize(raw);
            if (byEmail.TryGetValue(email, out var userId) && seen.Add(userId))
            {
                yield return (email, userId);
            }
        }
    }
}
