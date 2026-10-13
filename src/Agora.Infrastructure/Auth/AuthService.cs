using Agora.Application.Abstractions;
using Agora.Application.Constants;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Agora.Infrastructure.Auth;

public sealed class AuthService(
    AgoraDbContext db,
    IEmailSender emailSender,
    IBackgroundJobClient? backgroundJobs = null,
    LoginLockouts? loginLockouts = null,
    KeyedAsyncLock? ownerLocks = null)
{
    public const string TryAgainError = "Please try again.";
    private readonly LoginLockouts _lockouts = loginLockouts ?? new LoginLockouts(new MemoryCache(new MemoryCacheOptions()));
    /// <summary>Shared with <see cref="ShareManager"/>: share creation and account deletion serialize per owner.</summary>
    private readonly KeyedAsyncLock _ownerLocks = ownerLocks ?? new KeyedAsyncLock();

    public const string DevelopmentUserEmail = "dev@example.com";
    public const string EmailConfirmationRequiredError = "Please confirm your email before signing in.";
    /// <summary>The one failure message sign-in returns for a wrong password, an unknown, disabled or locked account.</summary>
    public const string LoginFailedError = "Invalid credentials.";
    private const string ConfirmationLinkError = "This confirmation link is invalid or expired.";
    private const string PasswordResetLinkError = "This password reset link is invalid or expired.";
    /// <summary>
    /// Verified against when the account does not exist, so an unknown address costs the same PBKDF2 work as a wrong
    /// password and the response time does not reveal whether the address is registered.
    /// </summary>
    private static readonly string DummyPasswordHash = PasswordHasher.Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
    private static readonly TimeSpan FailedAttemptWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan EmailConfirmationTokenLifetime = TimeSpan.FromHours(24);
    private static readonly TimeSpan PasswordResetTokenLifetime = TimeSpan.FromHours(2);
    private const int UploadTokenLength = 8;
    private static readonly Regex UploadTokenFormatRegex = new("^[A-Za-z0-9]{2,64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public async Task<(bool Success, string Error)> RegisterAsync(string email, string password, string confirmEmailUrlBase, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return (false, "Email and password are required.");
        }

        if (!IsValidEmail(email))
        {
            return (false, "Enter a valid email address.");
        }

        if (password.Length < 8)
        {
            return (false, "Password must be at least 8 characters.");
        }

        var userCount = await db.Users.CountAsync(cancellationToken);
        var allowRegistration = await GetAllowRegistrationAsync(cancellationToken);
        if (userCount > 0 && !allowRegistration)
        {
            return (false, "Registration is currently disabled.");
        }

        // An address that is already registered gets the same "check your email" outcome as a new one, so the
        // response reveals nothing about the account, and every branch costs one PBKDF2 run.
        var existing = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (existing is not null)
        {
            if (!existing.EmailConfirmed && existing.IsEnabled)
            {
                // Unconfirmed: whoever controls the mailbox claims the account. The newest registrant's password is
                // the one that becomes active when the address is confirmed; the stamp rotates and the earlier
                // confirmation link stops working, so a first registrant cannot plant a password the mailbox owner
                // later activates.
                existing.PasswordHash = PasswordHasher.Hash(password);
                existing.SecurityStamp = SecurityStamps.New();
                var claimToken = IssueEmailConfirmationToken(existing, DateTime.UtcNow);
                try
                {
                    await db.SaveChangesAsync(cancellationToken);
                }
                catch (DbUpdateConcurrencyException)
                {
                    // A concurrent change (for example the mailbox owner confirming) won; same response either way.
                    return (true, string.Empty);
                }

                await QueueAuthEmailAsync(ConfirmationEmail(existing.Email, confirmEmailUrlBase, claimToken), cancellationToken);
                return (true, string.Empty);
            }

            PasswordHasher.Verify(password, DummyPasswordHash);
            if (existing.EmailConfirmed)
            {
                await QueueAuthEmailAsync(new AuthEmailMessage(
                    To: existing.Email,
                    Subject: "You already have an Agora account",
                    Preheader: "Registration attempted for an existing account",
                    Headline: "This address is already registered",
                    IntroText: "Someone (probably you) tried to register an Agora account with this email address, but an account already exists.",
                    DetailText: "If this was you, sign in with your existing password or use \"Forgot password\" to set a new one.",
                    ActionLabel: null,
                    ActionUrl: null,
                    SecondaryText: "If this was not you, no action is needed; nothing about your account was changed."), cancellationToken);
            }

            // A disabled unconfirmed account stays disabled and untouched.
            return (true, string.Empty);
        }

        var isFirstUser = userCount == 0;
        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = email,
            DisplayName = DefaultDisplayNameForEmail(email),
            EmailConfirmed = false,
            PasswordHash = PasswordHasher.Hash(password),
            SecurityStamp = SecurityStamps.New(),
            Role = isFirstUser ? "admin" : "user",
            DefaultNotifyMode = "once",
            DefaultExpiryMode = "7_days",
            IsEnabled = true,
            UploadToken = await GenerateUniqueUploadTokenAsync(cancellationToken),
            UploadTokenUpdatedAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        db.Users.Add(user);
        await EnsureAccountTemplateAsync(user, cancellationToken);
        var token = IssueEmailConfirmationToken(user, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);

        await QueueAuthEmailAsync(ConfirmationEmail(user.Email, confirmEmailUrlBase, token), cancellationToken);
        return (true, string.Empty);
    }

    private static AuthEmailMessage ConfirmationEmail(string email, string confirmEmailUrlBase, string token) => new(
        To: email,
        Subject: "Confirm your email address",
        Preheader: "Complete your registration",
        Headline: "Confirm your email",
        IntroText: "Please confirm your email address before signing in to Agora.",
        DetailText: "If you did not request this account, you can ignore this email.",
        ActionLabel: "Confirm email",
        ActionUrl: BuildConfirmationUrl(confirmEmailUrlBase, email, token),
        SecondaryText: "This link expires in 24 hours.");

    /// <summary>
    /// Gives a new account its template row. A row left under the same address by an earlier account (deleted before
    /// templates were owned by id, or never backfilled) is reused with default content instead of inserting a
    /// duplicate address, so re-registering an address never fails on the unique index and never inherits the
    /// previous owner's design.
    /// </summary>
    private async Task EnsureAccountTemplateAsync(UserAccount user, CancellationToken cancellationToken)
    {
        var template = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == user.Email, cancellationToken);
        if (template is not null && template.OwnerUserId is { } ownerId && ownerId != user.Id &&
            await db.Users.AnyAsync(x => x.Id == ownerId, cancellationToken))
        {
            // Stale address on a live account's template (its owner changed email): point it at that account's
            // current address and give the newcomer a row of their own.
            template.UploaderEmail = await db.Users.Where(x => x.Id == ownerId).Select(x => x.Email).SingleAsync(cancellationToken);
            template = null;
        }

        if (template is null)
        {
            template = new AccountTemplate { Id = Guid.NewGuid() };
            db.AccountTemplates.Add(template);
        }

        template.OwnerUserId = user.Id;
        template.UploaderEmail = user.Email;
        template.Title = $"by {user.Email}";
        template.H1 = "A file was shared with you";
        template.Description = string.Empty;
        template.BackgroundImageUrl = null;
        template.BackgroundColorHex = null;
        template.ContainerPosition = "center";
        template.UpdatedAtUtc = DateTime.UtcNow;
    }

    public async Task ResendEmailConfirmationAsync(string email, string confirmEmailUrlBase, CancellationToken cancellationToken)
    {
        // Same cost for every account state, so timing reveals nothing about the address.
        PasswordHasher.Verify(string.Empty, DummyPasswordHash);
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || !IsValidEmail(email))
        {
            return;
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null || user.EmailConfirmed || !user.IsEnabled)
        {
            return;
        }

        await ResendEmailConfirmationAsync(user, confirmEmailUrlBase, cancellationToken);
    }

    private async Task ResendEmailConfirmationAsync(UserAccount user, string confirmEmailUrlBase, CancellationToken cancellationToken)
    {
        var token = IssueEmailConfirmationToken(user, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);
        await QueueAuthEmailAsync(ConfirmationEmail(user.Email, confirmEmailUrlBase, token), cancellationToken);
    }

    /// <summary>
    /// Signs in with an email and password. <paramref name="clientIp"/> keys the per-(account, address) lockout: five
    /// wrong passwords for one account from one address refuse that address for that account for a while, while other
    /// addresses with the correct password still sign in (so one attacker cannot lock the owner out).
    /// </summary>
    public async Task<(bool Success, string Error, UserAccount? User)> LoginAsync(string email, string password, string clientIp, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var nowUtc = DateTime.UtcNow;
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);

        // Every failure path costs one password verification and ends in the same message: an unknown address,
        // a wrong password, a disabled account and a locked address are indistinguishable to the caller. Only a
        // caller who presented the correct password learns that the account still needs its email confirmed.
        var passwordMatches = PasswordHasher.Verify(password ?? string.Empty, user?.PasswordHash ?? DummyPasswordHash);
        if (user is null)
        {
            return (false, LoginFailedError, null);
        }

        if (_lockouts.IsLockedOut(user.Id, clientIp))
        {
            // Locked for this address: the correct password is refused as well, and nothing is recorded.
            return (false, LoginFailedError, null);
        }

        if (!passwordMatches)
        {
            // Unconfirmed accounts accumulate nothing: they cannot be signed into anyway.
            if (user.EmailConfirmed)
            {
                RegisterFailedLoginAttempt(user, nowUtc);
                _lockouts.RecordFailure(user.Id, clientIp);
                try
                {
                    await db.SaveChangesAsync(cancellationToken);
                }
                catch (DbUpdateConcurrencyException)
                {
                    // A credential change raced the counter update; the counter is informational only.
                }
            }

            return (false, LoginFailedError, null);
        }

        _lockouts.Reset(user.Id, clientIp);
        if (!user.IsEnabled)
        {
            return (false, LoginFailedError, null);
        }

        if (!user.EmailConfirmed)
        {
            return (false, EmailConfirmationRequiredError, null);
        }

        var changed = false;
        if (user.FailedLoginCount != 0 || user.LastFailedLoginAtUtc is not null || user.LockoutEndUtc is not null)
        {
            user.FailedLoginCount = 0;
            user.LastFailedLoginAtUtc = null;
            user.LockoutEndUtc = null;
            changed = true;
        }

        // Rows created before security stamps existed get one at their first sign-in. Never rotate an existing
        // stamp here: a sign-in must not end the user's other sessions.
        if (string.IsNullOrEmpty(user.SecurityStamp))
        {
            user.SecurityStamp = SecurityStamps.New();
            changed = true;
        }

        if (changed)
        {
            try
            {
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateConcurrencyException)
            {
                // The credentials changed underneath this sign-in; the caller has to try again with the new ones.
                return (false, LoginFailedError, null);
            }
        }

        return (true, string.Empty, user);
    }

    public Task<UserAccount?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        return db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
    }

    public async Task<(UserAccount User, bool Created, string? GeneratedPassword)> EnsureDevelopmentUserAsync(CancellationToken cancellationToken)
    {
        var email = NormalizeEmail(DevelopmentUserEmail);
        var existing = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (existing is not null)
        {
            var changed = false;
            if (!existing.IsEnabled)
            {
                existing.IsEnabled = true;
                changed = true;
            }

            if (!existing.EmailConfirmed)
            {
                existing.EmailConfirmed = true;
                existing.EmailConfirmedAtUtc = DateTime.UtcNow;
                existing.EmailConfirmationTokenHash = null;
                existing.EmailConfirmationTokenExpiresAtUtc = null;
                changed = true;
            }

            if (existing.Role != "admin")
            {
                existing.Role = "admin";
                changed = true;
            }

            if (NormalizeNotifyMode(existing.DefaultNotifyMode) != existing.DefaultNotifyMode)
            {
                existing.DefaultNotifyMode = NormalizeNotifyMode(existing.DefaultNotifyMode);
                changed = true;
            }
            if (NormalizeExpiryMode(existing.DefaultExpiryMode) != existing.DefaultExpiryMode)
            {
                existing.DefaultExpiryMode = NormalizeExpiryMode(existing.DefaultExpiryMode);
                changed = true;
            }
            if (existing.FailedLoginCount != 0 || existing.LastFailedLoginAtUtc is not null || existing.LockoutEndUtc is not null)
            {
                existing.FailedLoginCount = 0;
                existing.LastFailedLoginAtUtc = null;
                existing.LockoutEndUtc = null;
                changed = true;
            }
            if (string.IsNullOrWhiteSpace(existing.UploadToken))
            {
                existing.UploadToken = await GenerateUniqueUploadTokenAsync(cancellationToken);
                existing.UploadTokenUpdatedAtUtc = DateTime.UtcNow;
                changed = true;
            }
            if (string.IsNullOrWhiteSpace(existing.DisplayName))
            {
                existing.DisplayName = DefaultDisplayNameForEmail(email);
                changed = true;
            }
            if (string.IsNullOrEmpty(existing.SecurityStamp))
            {
                existing.SecurityStamp = SecurityStamps.New();
                changed = true;
            }

            if (changed)
            {
                await db.SaveChangesAsync(cancellationToken);
            }

            return (existing, false, null);
        }

        var generatedPassword = GenerateDevelopmentPassword();
        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = email,
            DisplayName = DefaultDisplayNameForEmail(email),
            EmailConfirmed = true,
            EmailConfirmedAtUtc = DateTime.UtcNow,
            PasswordHash = PasswordHasher.Hash(generatedPassword),
            SecurityStamp = SecurityStamps.New(),
            Role = "admin",
            DefaultNotifyMode = "once",
            DefaultExpiryMode = "7_days",
            IsEnabled = true,
            UploadToken = await GenerateUniqueUploadTokenAsync(cancellationToken),
            UploadTokenUpdatedAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        db.Users.Add(user);
        await EnsureAccountTemplateAsync(user, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        return (user, true, generatedPassword);
    }

    public Task<List<UserAccount>> GetUsersAsync(CancellationToken cancellationToken)
    {
        return db.Users.OrderBy(x => x.Email).ToListAsync(cancellationToken);
    }

    public async Task<bool> UpdateRoleAsync(Guid userId, string role, CancellationToken cancellationToken)
    {
        role = role.Trim().ToLowerInvariant();
        if (role is not ("admin" or "user"))
        {
            return false;
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        if (user.Role == "admin" && role == "user")
        {
            var adminCount = await db.Users.CountAsync(x => x.Role == "admin" && x.IsEnabled, cancellationToken);
            if (adminCount <= 1)
            {
                return false;
            }
        }

        if (user.Role == role)
        {
            return true;
        }

        user.Role = role;
        user.SecurityStamp = SecurityStamps.New();
        return await TrySaveUserChangeAsync(cancellationToken);
    }

    public async Task<bool> SetEnabledAsync(Guid userId, bool enabled, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        if (user.Role == "admin" && !enabled)
        {
            var adminCount = await db.Users.CountAsync(x => x.Role == "admin" && x.IsEnabled, cancellationToken);
            if (adminCount <= 1)
            {
                return false;
            }
        }

        if (user.IsEnabled == enabled)
        {
            return true;
        }

        user.IsEnabled = enabled;
        user.SecurityStamp = SecurityStamps.New();
        return await TrySaveUserChangeAsync(cancellationToken);
    }

    /// <summary>Saves a change of the user row; false when a concurrent change of the same row won (stamp mismatch).</summary>
    private async Task<bool> TrySaveUserChangeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            return false;
        }
    }

    public async Task<bool> DeleteUserAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        if (user.Role == "admin")
        {
            var adminCount = await db.Users.CountAsync(x => x.Role == "admin" && x.IsEnabled, cancellationToken);
            if (adminCount <= 1)
            {
                return false;
            }
        }

        // Everything the account owns goes with it: the template row (its address would otherwise block
        // re-registration on the unique index) and the shares, which take the regular delete path (soft-deleted now,
        // content removed by the background job), so nothing is left for a later account under the same address.
        // The per-owner lock keeps a share creation from slipping in between the snapshot and the delete.
        List<Share> shares;
        using (await _ownerLocks.LockAsync(ShareManager.OwnerLockKey(userId), cancellationToken))
        {
            var templates = await db.AccountTemplates.Where(x => x.OwnerUserId == userId).ToListAsync(cancellationToken);
            db.AccountTemplates.RemoveRange(templates);
            shares = await db.Shares.Where(x => x.OwnerUserId == userId && x.DeletedAtUtc == null).ToListAsync(cancellationToken);
            var now = DateTime.UtcNow;
            foreach (var share in shares)
            {
                share.DeletedAtUtc = now;
            }

            db.Users.Remove(user);
            if (!await TrySaveUserChangeAsync(cancellationToken))
            {
                return false;
            }
        }

        if (backgroundJobs is not null)
        {
            foreach (var share in shares)
            {
                var shareId = share.Id;
                backgroundJobs.Enqueue<ShareManager>(x => x.DeleteShareFilesAsync(shareId, CancellationToken.None));
            }
        }

        return true;
    }

    public async Task<UserAccount?> FindByUploadTokenAsync(string uploadToken, CancellationToken cancellationToken)
    {
        var normalizedToken = NormalizeUploadToken(uploadToken);
        if (string.IsNullOrWhiteSpace(normalizedToken))
        {
            return null;
        }

        return await db.Users.SingleOrDefaultAsync(
            x => x.UploadToken == normalizedToken && x.IsEnabled,
            cancellationToken);
    }

    // Signed-in operations identify the account by the id claim of the session; the email is never an authorization
    // key. A save that loses against a concurrent change of the same row returns a controlled failure.

    public async Task<string?> GetOrCreateUploadTokenAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(user.UploadToken))
        {
            return user.UploadToken;
        }

        user.UploadToken = await GenerateUniqueUploadTokenAsync(cancellationToken);
        user.UploadTokenUpdatedAtUtc = DateTime.UtcNow;
        return await TrySaveUserChangeAsync(cancellationToken) ? user.UploadToken : null;
    }

    public async Task<string?> RegenerateUploadTokenAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return null;
        }

        user.UploadToken = await GenerateUniqueUploadTokenAsync(cancellationToken);
        user.UploadTokenUpdatedAtUtc = DateTime.UtcNow;
        return await TrySaveUserChangeAsync(cancellationToken) ? user.UploadToken : null;
    }

    public async Task<(bool Success, string Error, string? DisplayName)> SetDisplayNameAsync(Guid userId, string displayName, CancellationToken cancellationToken)
    {
        var normalized = (displayName ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return (false, "Name is required.", null);
        }

        if (normalized.Length > 200)
        {
            return (false, "Name must be 200 characters or fewer.", null);
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return (false, "Account not found.", null);
        }

        user.DisplayName = normalized;
        return await TrySaveUserChangeAsync(cancellationToken)
            ? (true, string.Empty, user.DisplayName)
            : (false, TryAgainError, null);
    }

    public async Task<(bool Success, string Error, string? UploadToken)> SetUploadTokenAsync(Guid userId, string requestedToken, CancellationToken cancellationToken)
    {
        var normalizedToken = NormalizeUploadToken(requestedToken);
        if (!IsValidUploadToken(normalizedToken))
        {
            return (false, "Upload code must be 2-64 letters or numbers.", null);
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return (false, "Account not found.", null);
        }

        var isTaken = await db.Users.AnyAsync(
            x => x.UploadToken == normalizedToken && x.Id != user.Id,
            cancellationToken);
        if (isTaken)
        {
            return (false, "That upload code is already in use.", null);
        }

        user.UploadToken = normalizedToken;
        user.UploadTokenUpdatedAtUtc = DateTime.UtcNow;
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return (false, TryAgainError, null);
        }
        catch (DbUpdateException ex) when (IsUploadTokenConflict(ex))
        {
            return (false, "That upload code is already in use.", null);
        }

        return (true, string.Empty, user.UploadToken);
    }

    public async Task<bool> GetAllowRegistrationAsync(CancellationToken cancellationToken)
    {
        var setting = await db.SystemSettings.SingleOrDefaultAsync(x => x.Key == SystemSettingKeys.AllowRegistration, cancellationToken);
        if (setting is null)
        {
            setting = new SystemSetting
            {
                Key = SystemSettingKeys.AllowRegistration,
                Value = "true",
                UpdatedAtUtc = DateTime.UtcNow
            };
            db.SystemSettings.Add(setting);
            try
            {
                await db.SaveChangesAsync(cancellationToken);
                return true;
            }
            catch (DbUpdateException)
            {
                db.Entry(setting).State = EntityState.Detached;
                var existing = await db.SystemSettings.SingleOrDefaultAsync(x => x.Key == SystemSettingKeys.AllowRegistration, cancellationToken);
                if (existing is null)
                {
                    throw;
                }

                return string.Equals(existing.Value, "true", StringComparison.OrdinalIgnoreCase);
            }
        }

        return string.Equals(setting.Value, "true", StringComparison.OrdinalIgnoreCase);
    }

    public async Task SetAllowRegistrationAsync(bool enabled, CancellationToken cancellationToken)
    {
        var setting = await db.SystemSettings.SingleOrDefaultAsync(x => x.Key == SystemSettingKeys.AllowRegistration, cancellationToken);
        if (setting is null)
        {
            db.SystemSettings.Add(new SystemSetting
            {
                Key = SystemSettingKeys.AllowRegistration,
                Value = enabled ? "true" : "false",
                UpdatedAtUtc = DateTime.UtcNow
            });
        }
        else
        {
            setting.Value = enabled ? "true" : "false";
            setting.UpdatedAtUtc = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<string> GetDefaultNotifyModeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        return user is null ? "once" : NormalizeNotifyMode(user.DefaultNotifyMode);
    }

    public async Task<bool> SetDefaultNotifyModeAsync(Guid userId, string notifyMode, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        user.DefaultNotifyMode = NormalizeNotifyMode(notifyMode);
        return await TrySaveUserChangeAsync(cancellationToken);
    }

    public async Task<string> GetDefaultExpiryModeAsync(Guid userId, CancellationToken cancellationToken)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        return user is null ? "7_days" : NormalizeExpiryMode(user.DefaultExpiryMode);
    }

    public async Task<bool> SetDefaultExpiryModeAsync(Guid userId, string expiryMode, CancellationToken cancellationToken)
    {
        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return false;
        }

        user.DefaultExpiryMode = NormalizeExpiryMode(expiryMode);
        return await TrySaveUserChangeAsync(cancellationToken);
    }

    public async Task<(bool Success, string Error)> ConfirmEmailAsync(string email, string token, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return (false, ConfirmationLinkError);
        }

        // Unknown address, already confirmed account and bad token all read the same, so the link endpoint cannot be
        // used to probe which addresses have an account or whether it was confirmed.
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null || user.EmailConfirmed ||
            !IsTokenValid(user.EmailConfirmationTokenHash, user.EmailConfirmationTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, ConfirmationLinkError);
        }

        user.EmailConfirmed = true;
        user.EmailConfirmedAtUtc = DateTime.UtcNow;
        user.EmailConfirmationTokenHash = null;
        user.EmailConfirmationTokenExpiresAtUtc = null;
        // Rotated so a registration that loaded this row before the confirmation (a claim in flight) fails its save
        // instead of replacing the password the confirming owner just activated.
        user.SecurityStamp = SecurityStamps.New();
        return await TrySaveUserChangeAsync(cancellationToken) ? (true, string.Empty) : (false, ConfirmationLinkError);
    }

    public async Task<(bool Success, string Error)> RequestEmailChangeAsync(
        Guid userId,
        string newEmail,
        string currentPassword,
        string confirmEmailChangeUrlBase,
        CancellationToken cancellationToken)
    {
        newEmail = NormalizeEmail(newEmail);

        if (string.IsNullOrWhiteSpace(newEmail))
        {
            return (false, "New email is required.");
        }

        if (!IsValidEmail(newEmail))
        {
            return (false, "Enter a valid email address.");
        }

        if (string.IsNullOrWhiteSpace(currentPassword))
        {
            return (false, "Current password is required.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return (false, "Account not found.");
        }

        if (!PasswordHasher.Verify(currentPassword, user.PasswordHash))
        {
            return (false, "Current password is incorrect.");
        }

        if (string.Equals(user.Email, newEmail, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "That is already your current email.");
        }

        if (await db.Users.AnyAsync(x => x.Email == newEmail && x.Id != user.Id, cancellationToken))
        {
            return (false, "A user with this email already exists.");
        }

        var token = IssuePendingEmailToken(user, newEmail, DateTime.UtcNow);
        if (!await TrySaveUserChangeAsync(cancellationToken))
        {
            return (false, TryAgainError);
        }

        var confirmationUrl = BuildConfirmationUrl(confirmEmailChangeUrlBase, user.Email, token);
        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: newEmail,
            Subject: "Confirm your new email address",
            Preheader: "Email change confirmation required",
            Headline: "Confirm your new email",
            IntroText: "Confirm this email address to complete your account email change.",
            DetailText: $"Current account email: {user.Email}",
            ActionLabel: "Confirm email change",
            ActionUrl: confirmationUrl,
            SecondaryText: "This link expires in 24 hours."), cancellationToken);

        return (true, string.Empty);
    }

    public async Task<(bool Success, string Error)> ConfirmEmailChangeAsync(string currentEmail, string token, CancellationToken cancellationToken)
    {
        currentEmail = NormalizeEmail(currentEmail);
        if (string.IsNullOrWhiteSpace(currentEmail) || string.IsNullOrWhiteSpace(token))
        {
            return (false, ConfirmationLinkError);
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == currentEmail, cancellationToken);
        if (user is null || !IsTokenValid(user.PendingEmailTokenHash, user.PendingEmailTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, ConfirmationLinkError);
        }

        var nextEmail = NormalizeEmail(user.PendingEmail ?? string.Empty);
        if (string.IsNullOrWhiteSpace(nextEmail) || !IsValidEmail(nextEmail))
        {
            return (false, "Pending email change is invalid.");
        }

        if (await db.Users.AnyAsync(x => x.Email == nextEmail && x.Id != user.Id, cancellationToken))
        {
            return (false, "That email address is already in use.");
        }

        var previousEmail = user.Email;
        var userId = user.Id;

        // The user row, the template, the share display addresses and the token consumption change together or not
        // at all; a concurrent credential change (stamp mismatch) rolls everything back.
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            // A template row left at the new address by an earlier account would collide on the unique index: a row
            // whose owner still exists is pointed at that owner's current address, an orphan is removed. Saved first
            // so the rename below never races it.
            var staleTemplates = await db.AccountTemplates
                .Where(x => x.UploaderEmail == nextEmail && x.OwnerUserId != userId)
                .ToListAsync(cancellationToken);
            foreach (var stale in staleTemplates)
            {
                var ownerId = stale.OwnerUserId;
                var ownerEmail = ownerId is null
                    ? null
                    : await db.Users.Where(x => x.Id == ownerId).Select(x => x.Email).SingleOrDefaultAsync(cancellationToken);
                if (ownerEmail is null)
                {
                    db.AccountTemplates.Remove(stale);
                }
                else
                {
                    stale.UploaderEmail = ownerEmail;
                }
            }

            if (staleTemplates.Count > 0)
            {
                await db.SaveChangesAsync(cancellationToken);
            }

            user.Email = nextEmail;
            ClearPendingCredentialTokens(user);
            user.SecurityStamp = SecurityStamps.New();

            var accountTemplate = await db.AccountTemplates.SingleOrDefaultAsync(x => x.OwnerUserId == userId, cancellationToken);
            if (accountTemplate is not null)
            {
                accountTemplate.UploaderEmail = nextEmail;
                var expectedOldTitle = $"by {previousEmail}";
                if (string.Equals(accountTemplate.Title, expectedOldTitle, StringComparison.OrdinalIgnoreCase))
                {
                    accountTemplate.Title = $"by {nextEmail}";
                }
            }

            await db.SaveChangesAsync(cancellationToken);

            // Shares are owned by id; their display address follows the account.
            await db.Shares
                .Where(x => x.OwnerUserId == userId)
                .ExecuteUpdateAsync(set => set.SetProperty(x => x.UploaderEmail, nextEmail), cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return (false, ConfirmationLinkError);
        }

        // The previous address is told first: it is the one that can still act if the change was not legitimate.
        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: previousEmail,
            Subject: "Your email address was changed",
            Preheader: "Account email updated",
            Headline: "Email address changed",
            IntroText: $"The email address of your Agora account was changed from this address to {user.Email}.",
            DetailText: "Sign-in and all account emails now go to the new address; this address no longer belongs to the account.",
            ActionLabel: null,
            ActionUrl: null,
            SecondaryText: "If you did not make this change, contact your administrator immediately."), cancellationToken);

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Your email address was changed",
            Preheader: "Account email updated",
            Headline: "Email address updated",
            IntroText: "Your Agora account email address has been changed successfully.",
            DetailText: $"Previous email: {previousEmail}\nNew email: {user.Email}",
            ActionLabel: null,
            ActionUrl: null,
            SecondaryText: "If you did not make this change, reset your password immediately."), cancellationToken);

        return (true, string.Empty);
    }

    public async Task<(bool Success, string Error)> RequestPasswordChangeAsync(
        Guid userId,
        string currentPassword,
        string newPassword,
        string confirmPasswordChangeUrlBase,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(currentPassword))
        {
            return (false, "Current password is required.");
        }

        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return (false, "New password is required.");
        }

        if (newPassword.Length < 8)
        {
            return (false, "New password must be at least 8 characters.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, cancellationToken);
        if (user is null)
        {
            return (false, "Account not found.");
        }

        if (!PasswordHasher.Verify(currentPassword, user.PasswordHash))
        {
            return (false, "Current password is incorrect.");
        }

        if (PasswordHasher.Verify(newPassword, user.PasswordHash))
        {
            return (false, "New password must be different from the current password.");
        }

        var token = IssuePendingPasswordToken(user, newPassword, DateTime.UtcNow);
        if (!await TrySaveUserChangeAsync(cancellationToken))
        {
            return (false, TryAgainError);
        }

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Confirm your password change",
            Preheader: "Password change confirmation required",
            Headline: "Confirm password change",
            IntroText: "Confirm this request to update your account password.",
            DetailText: "For security, the change is applied only after you confirm by email.",
            ActionLabel: "Confirm password change",
            ActionUrl: BuildConfirmationUrl(confirmPasswordChangeUrlBase, user.Email, token),
            SecondaryText: "This link expires in 24 hours."), cancellationToken);

        return (true, string.Empty);
    }

    public async Task<(bool Success, string Error)> ConfirmPasswordChangeAsync(string email, string token, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return (false, ConfirmationLinkError);
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null ||
            !IsTokenValid(user.PendingPasswordTokenHash, user.PendingPasswordTokenExpiresAtUtc, token, DateTime.UtcNow) ||
            string.IsNullOrWhiteSpace(user.PendingPasswordHash))
        {
            return (false, ConfirmationLinkError);
        }

        user.PasswordHash = user.PendingPasswordHash;
        ClearPendingCredentialTokens(user);
        user.SecurityStamp = SecurityStamps.New();
        if (!await TrySaveUserChangeAsync(cancellationToken))
        {
            return (false, ConfirmationLinkError);
        }

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Your password was changed",
            Preheader: "Account password updated",
            Headline: "Password updated",
            IntroText: "Your Agora account password has been changed successfully.",
            DetailText: "If this was not you, use forgot password immediately and secure your account.",
            ActionLabel: null,
            ActionUrl: null,
            SecondaryText: null), cancellationToken);

        return (true, string.Empty);
    }

    public async Task RequestPasswordResetAsync(string email, string resetPasswordUrlBase, CancellationToken cancellationToken)
    {
        // Same cost for every account state, so timing reveals nothing about the address.
        PasswordHasher.Verify(string.Empty, DummyPasswordHash);
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || !IsValidEmail(email))
        {
            return;
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null || !user.EmailConfirmed || !user.IsEnabled)
        {
            return;
        }

        var token = IssuePasswordResetToken(user, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Reset your password",
            Preheader: "Password reset requested",
            Headline: "Reset your password",
            IntroText: "We received a request to reset your password.",
            DetailText: "If you did not request this, you can ignore this email.",
            ActionLabel: "Reset password",
            ActionUrl: BuildConfirmationUrl(resetPasswordUrlBase, user.Email, token),
            SecondaryText: "This link expires in 2 hours."), cancellationToken);
    }

    public async Task<(bool Success, string Error)> ResetPasswordAsync(string email, string token, string newPassword, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return (false, PasswordResetLinkError);
        }

        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8)
        {
            return (false, "Password must be at least 8 characters.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null || !IsTokenValid(user.PasswordResetTokenHash, user.PasswordResetTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, PasswordResetLinkError);
        }

        user.PasswordHash = PasswordHasher.Hash(newPassword);
        ClearPendingCredentialTokens(user);
        user.SecurityStamp = SecurityStamps.New();
        if (!await TrySaveUserChangeAsync(cancellationToken))
        {
            return (false, PasswordResetLinkError);
        }

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Your password was changed",
            Preheader: "Account password updated",
            Headline: "Password updated",
            IntroText: "Your Agora account password has been reset successfully.",
            DetailText: "If this was not you, reset your password again immediately.",
            ActionLabel: null,
            ActionUrl: null,
            SecondaryText: null), cancellationToken);

        return (true, string.Empty);
    }

    private static string NormalizeEmail(string value) => EmailAddress.Normalize(value);

    /// <summary>
    /// Invalidates every outstanding token of the account. Called on each credential change (password change
    /// confirmed, password reset, email change confirmed) so that, for example, an email change started by an
    /// attacker cannot be completed after the owner has reset the password.
    /// </summary>
    private static void ClearPendingCredentialTokens(UserAccount user)
    {
        user.EmailConfirmationTokenHash = null;
        user.EmailConfirmationTokenExpiresAtUtc = null;
        user.PendingEmail = null;
        user.PendingEmailTokenHash = null;
        user.PendingEmailTokenExpiresAtUtc = null;
        user.PendingPasswordHash = null;
        user.PendingPasswordTokenHash = null;
        user.PendingPasswordTokenExpiresAtUtc = null;
        user.PasswordResetTokenHash = null;
        user.PasswordResetTokenExpiresAtUtc = null;
    }

    private static string DefaultDisplayNameForEmail(string email)
    {
        var normalized = NormalizeEmail(email);
        var at = normalized.IndexOf('@');
        var local = at > 0 ? normalized[..at] : normalized;
        var candidate = local.Trim();
        if (candidate.Length == 0)
        {
            return "User";
        }

        return candidate.Length <= 200 ? candidate : candidate[..200];
    }

    private static string NormalizeUploadToken(string value)
    {
        return (value ?? string.Empty).Trim();
    }

    private static bool IsValidUploadToken(string token)
    {
        return UploadTokenFormatRegex.IsMatch(token);
    }

    private Task QueueAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        if (backgroundJobs is null)
        {
            return emailSender.SendAuthEmailAsync(message, cancellationToken);
        }

        backgroundJobs.Enqueue<AuthEmailJob>(x => x.SendAsync(message, CancellationToken.None, null));
        return Task.CompletedTask;
    }

    private static string GenerateDevelopmentPassword()
    {
        Span<byte> bytes = stackalloc byte[18];
        RandomNumberGenerator.Fill(bytes);
        var password = Convert.ToBase64String(bytes);
        return password.Replace('+', '-').Replace('/', '_');
    }

    private static string NormalizeNotifyMode(string value)
    {
        var mode = (value ?? string.Empty).Trim().ToLowerInvariant();
        return mode is "none" or "once" or "every_time" ? mode : "once";
    }

    private static string NormalizeExpiryMode(string value)
    {
        var mode = (value ?? string.Empty).Trim().ToLowerInvariant();
        return mode is "1_hour" or "24_hours" or "7_days" or "30_days" or "1_year" or "indefinite"
            ? mode
            : "7_days";
    }

    private static bool IsValidEmail(string value)
    {
        try
        {
            var parsed = new MailAddress(value);
            return string.Equals(parsed.Address, value, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Per-account failure counters, kept for admin visibility; blocking is per (account, address) in <see cref="LoginLockouts"/>.</summary>
    private static void RegisterFailedLoginAttempt(UserAccount user, DateTime nowUtc)
    {
        var resetWindow = user.LastFailedLoginAtUtc is null || (nowUtc - user.LastFailedLoginAtUtc.Value) > FailedAttemptWindow;
        user.FailedLoginCount = resetWindow ? 1 : user.FailedLoginCount + 1;
        user.LastFailedLoginAtUtc = nowUtc;
    }

    private static bool IsTokenValid(string? hash, DateTime? expiresAtUtc, string token, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(hash) || expiresAtUtc is null || expiresAtUtc <= nowUtc)
        {
            return false;
        }

        return string.Equals(hash, TokenCodec.HashToken(token), StringComparison.Ordinal);
    }

    private static string BuildConfirmationUrl(string baseUrl, string email, string token)
    {
        var separator = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{baseUrl}{separator}email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(token)}";
    }

    private async Task<string> GenerateUniqueUploadTokenAsync(CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 64; attempt += 1)
        {
            var candidate = TokenCodec.GenerateAlphanumericToken(UploadTokenLength);
            var exists = await db.Users.AnyAsync(x => x.UploadToken == candidate, cancellationToken);
            if (!exists)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("Unable to generate a unique upload token right now.");
    }

    private static bool IsUploadTokenConflict(DbUpdateException ex)
    {
        var text = ex.ToString();
        return text.Contains("UploadToken", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("IX_Users_UploadToken", StringComparison.OrdinalIgnoreCase);
    }

    private static string IssueEmailConfirmationToken(UserAccount user, DateTime nowUtc)
    {
        var token = TokenCodec.GenerateToken();
        user.EmailConfirmationTokenHash = TokenCodec.HashToken(token);
        user.EmailConfirmationTokenExpiresAtUtc = nowUtc.Add(EmailConfirmationTokenLifetime);
        return token;
    }

    private static string IssuePendingEmailToken(UserAccount user, string pendingEmail, DateTime nowUtc)
    {
        var token = TokenCodec.GenerateToken();
        user.PendingEmail = pendingEmail;
        user.PendingEmailTokenHash = TokenCodec.HashToken(token);
        user.PendingEmailTokenExpiresAtUtc = nowUtc.Add(EmailConfirmationTokenLifetime);
        return token;
    }

    private static string IssuePendingPasswordToken(UserAccount user, string newPassword, DateTime nowUtc)
    {
        var token = TokenCodec.GenerateToken();
        user.PendingPasswordHash = PasswordHasher.Hash(newPassword);
        user.PendingPasswordTokenHash = TokenCodec.HashToken(token);
        user.PendingPasswordTokenExpiresAtUtc = nowUtc.Add(EmailConfirmationTokenLifetime);
        return token;
    }

    private static string IssuePasswordResetToken(UserAccount user, DateTime nowUtc)
    {
        var token = TokenCodec.GenerateToken();
        user.PasswordResetTokenHash = TokenCodec.HashToken(token);
        user.PasswordResetTokenExpiresAtUtc = nowUtc.Add(PasswordResetTokenLifetime);
        return token;
    }
}
