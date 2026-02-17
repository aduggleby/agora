using Agora.Application.Abstractions;
using Agora.Application.Constants;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Agora.Infrastructure.Services;
using Hangfire;
using Microsoft.EntityFrameworkCore;
using System.Net.Mail;
using System.Security.Cryptography;

namespace Agora.Infrastructure.Auth;

public sealed class AuthService(
    AgoraDbContext db,
    IEmailSender emailSender,
    IBackgroundJobClient? backgroundJobs = null)
{
    public const string DevelopmentUserEmail = "ad@dualconsult.com";
    public const string EmailConfirmationRequiredError = "Please confirm your email before signing in.";
    private const int MaxFailedLoginAttempts = 5;
    private static readonly TimeSpan FailedAttemptWindow = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan EmailConfirmationTokenLifetime = TimeSpan.FromHours(24);
    private static readonly TimeSpan PasswordResetTokenLifetime = TimeSpan.FromHours(2);

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

        var existing = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        UserAccount user;
        if (existing is not null)
        {
            if (existing.EmailConfirmed)
            {
                return (false, "A user with this email already exists.");
            }

            user = existing;
            user.PasswordHash = PasswordHasher.Hash(password);
            user.IsEnabled = true;
        }
        else
        {
            var isFirstUser = userCount == 0;
            user = new UserAccount
            {
                Id = Guid.NewGuid(),
                Email = email,
                EmailConfirmed = false,
                PasswordHash = PasswordHasher.Hash(password),
                Role = isFirstUser ? "admin" : "user",
                DefaultNotifyMode = "once",
                DefaultExpiryMode = "7_days",
                IsEnabled = true,
                CreatedAtUtc = DateTime.UtcNow
            };

            db.Users.Add(user);
            db.AccountTemplates.Add(new AccountTemplate
            {
                Id = Guid.NewGuid(),
                UploaderEmail = email,
                Title = $"by {email}",
                H1 = "A file was shared with you",
                Description = "Use the button below to download your file.",
                UpdatedAtUtc = DateTime.UtcNow
            });
        }

        var token = IssueEmailConfirmationToken(user, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Confirm your email address",
            Preheader: "Complete your registration",
            Headline: "Confirm your email",
            IntroText: "Please confirm your email address before signing in to Agora.",
            DetailText: "If you did not request this account, you can ignore this email.",
            ActionLabel: "Confirm email",
            ActionUrl: BuildConfirmationUrl(confirmEmailUrlBase, user.Email, token),
            SecondaryText: "This link expires in 24 hours."), cancellationToken);

        return (true, string.Empty);
    }

    public async Task ResendEmailConfirmationAsync(string email, string confirmEmailUrlBase, CancellationToken cancellationToken)
    {
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

        var token = IssueEmailConfirmationToken(user, DateTime.UtcNow);
        await db.SaveChangesAsync(cancellationToken);

        await QueueAuthEmailAsync(new AuthEmailMessage(
            To: user.Email,
            Subject: "Confirm your email address",
            Preheader: "Complete your registration",
            Headline: "Confirm your email",
            IntroText: "Please confirm your email address before signing in to Agora.",
            DetailText: "If you did not request this account, you can ignore this email.",
            ActionLabel: "Confirm email",
            ActionUrl: BuildConfirmationUrl(confirmEmailUrlBase, user.Email, token),
            SecondaryText: "This link expires in 24 hours."), cancellationToken);
    }

    public async Task<(bool Success, string Error, UserAccount? User)> LoginAsync(string email, string password, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var nowUtc = DateTime.UtcNow;
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid credentials.", null);
        }

        if (!user.IsEnabled)
        {
            return (false, "This account is disabled.", null);
        }

        if (!user.EmailConfirmed)
        {
            return (false, EmailConfirmationRequiredError, null);
        }

        if (user.LockoutEndUtc is not null && user.LockoutEndUtc > nowUtc)
        {
            return (false, "Too many failed login attempts. Try again later.", null);
        }

        var lockoutExpired = user.LockoutEndUtc is not null && user.LockoutEndUtc <= nowUtc;
        if (lockoutExpired)
        {
            user.LockoutEndUtc = null;
            user.FailedLoginCount = 0;
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
        {
            RegisterFailedLoginAttempt(user, nowUtc);
            await db.SaveChangesAsync(cancellationToken);
            if (user.LockoutEndUtc is not null && user.LockoutEndUtc > nowUtc)
            {
                return (false, "Too many failed login attempts. Try again later.", null);
            }

            return (false, "Invalid credentials.", null);
        }

        if (user.FailedLoginCount != 0 || user.LastFailedLoginAtUtc is not null || user.LockoutEndUtc is not null)
        {
            user.FailedLoginCount = 0;
            user.LastFailedLoginAtUtc = null;
            user.LockoutEndUtc = null;
            await db.SaveChangesAsync(cancellationToken);
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
            EmailConfirmed = true,
            EmailConfirmedAtUtc = DateTime.UtcNow,
            PasswordHash = PasswordHasher.Hash(generatedPassword),
            Role = "admin",
            DefaultNotifyMode = "once",
            DefaultExpiryMode = "7_days",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow
        };

        db.Users.Add(user);
        db.AccountTemplates.Add(new AccountTemplate
        {
            Id = Guid.NewGuid(),
            UploaderEmail = email,
            Title = $"by {email}",
            H1 = "A file was shared with you",
            Description = "Use the button below to download your file.",
            UpdatedAtUtc = DateTime.UtcNow
        });
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

        user.Role = role;
        await db.SaveChangesAsync(cancellationToken);
        return true;
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

        user.IsEnabled = enabled;
        await db.SaveChangesAsync(cancellationToken);
        return true;
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

        db.Users.Remove(user);
        await db.SaveChangesAsync(cancellationToken);
        return true;
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

    public async Task<string> GetDefaultNotifyModeAsync(string email, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return "once";
        }

        return NormalizeNotifyMode(user.DefaultNotifyMode);
    }

    public async Task<bool> SetDefaultNotifyModeAsync(string email, string notifyMode, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return false;
        }

        user.DefaultNotifyMode = NormalizeNotifyMode(notifyMode);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<string> GetDefaultExpiryModeAsync(string email, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return "7_days";
        }

        return NormalizeExpiryMode(user.DefaultExpiryMode);
    }

    public async Task<bool> SetDefaultExpiryModeAsync(string email, string expiryMode, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return false;
        }

        user.DefaultExpiryMode = NormalizeExpiryMode(expiryMode);
        await db.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<(bool Success, string Error)> ConfirmEmailAsync(string email, string token, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return (false, "Invalid confirmation link.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid confirmation link.");
        }

        if (user.EmailConfirmed)
        {
            return (true, string.Empty);
        }

        if (!IsTokenValid(user.EmailConfirmationTokenHash, user.EmailConfirmationTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, "This confirmation link is invalid or expired.");
        }

        user.EmailConfirmed = true;
        user.EmailConfirmedAtUtc = DateTime.UtcNow;
        user.EmailConfirmationTokenHash = null;
        user.EmailConfirmationTokenExpiresAtUtc = null;
        await db.SaveChangesAsync(cancellationToken);
        return (true, string.Empty);
    }

    public async Task<(bool Success, string Error)> RequestEmailChangeAsync(
        string currentEmail,
        string newEmail,
        string currentPassword,
        string confirmEmailChangeUrlBase,
        CancellationToken cancellationToken)
    {
        currentEmail = NormalizeEmail(currentEmail);
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

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == currentEmail, cancellationToken);
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
        await db.SaveChangesAsync(cancellationToken);

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
            return (false, "Invalid confirmation link.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == currentEmail, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid confirmation link.");
        }

        if (!IsTokenValid(user.PendingEmailTokenHash, user.PendingEmailTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, "This confirmation link is invalid or expired.");
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
        user.Email = nextEmail;
        user.PendingEmail = null;
        user.PendingEmailTokenHash = null;
        user.PendingEmailTokenExpiresAtUtc = null;

        var accountTemplate = await db.AccountTemplates.SingleOrDefaultAsync(x => x.UploaderEmail == previousEmail, cancellationToken);
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
        string email,
        string currentPassword,
        string newPassword,
        string confirmPasswordChangeUrlBase,
        CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
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

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
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
        await db.SaveChangesAsync(cancellationToken);

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
            return (false, "Invalid confirmation link.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid confirmation link.");
        }

        if (!IsTokenValid(user.PendingPasswordTokenHash, user.PendingPasswordTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, "This confirmation link is invalid or expired.");
        }

        if (string.IsNullOrWhiteSpace(user.PendingPasswordHash))
        {
            return (false, "No pending password change found.");
        }

        user.PasswordHash = user.PendingPasswordHash;
        user.PendingPasswordHash = null;
        user.PendingPasswordTokenHash = null;
        user.PendingPasswordTokenExpiresAtUtc = null;
        await db.SaveChangesAsync(cancellationToken);

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
            return (false, "Invalid password reset link.");
        }

        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8)
        {
            return (false, "Password must be at least 8 characters.");
        }

        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid password reset link.");
        }

        if (!IsTokenValid(user.PasswordResetTokenHash, user.PasswordResetTokenExpiresAtUtc, token, DateTime.UtcNow))
        {
            return (false, "This password reset link is invalid or expired.");
        }

        user.PasswordHash = PasswordHasher.Hash(newPassword);
        user.PasswordResetTokenHash = null;
        user.PasswordResetTokenExpiresAtUtc = null;
        user.PendingPasswordHash = null;
        user.PendingPasswordTokenHash = null;
        user.PendingPasswordTokenExpiresAtUtc = null;
        await db.SaveChangesAsync(cancellationToken);

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

    private static string NormalizeEmail(string value)
    {
        return (value ?? string.Empty).Trim().ToLowerInvariant();
    }

    private Task QueueAuthEmailAsync(AuthEmailMessage message, CancellationToken cancellationToken)
    {
        if (backgroundJobs is null)
        {
            return emailSender.SendAuthEmailAsync(message, cancellationToken);
        }

        backgroundJobs.Enqueue<AuthEmailJob>(x => x.SendAsync(message, CancellationToken.None));
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

    private static void RegisterFailedLoginAttempt(UserAccount user, DateTime nowUtc)
    {
        var resetWindow = user.LastFailedLoginAtUtc is null || (nowUtc - user.LastFailedLoginAtUtc.Value) > FailedAttemptWindow;
        user.FailedLoginCount = resetWindow ? 1 : user.FailedLoginCount + 1;
        user.LastFailedLoginAtUtc = nowUtc;
        if (user.FailedLoginCount >= MaxFailedLoginAttempts)
        {
            user.LockoutEndUtc = nowUtc.Add(LockoutDuration);
        }
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
