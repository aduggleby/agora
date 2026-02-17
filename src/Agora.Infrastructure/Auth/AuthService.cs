using Agora.Application.Constants;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Agora.Infrastructure.Auth;

public sealed class AuthService(AgoraDbContext db)
{
    public const string DevelopmentUserEmail = "ad@dualconsult.com";

    public async Task<(bool Success, string Error, UserAccount? User)> RegisterAsync(string email, string password, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return (false, "Email and password are required.", null);
        }

        if (await db.Users.AnyAsync(x => x.Email == email, cancellationToken))
        {
            return (false, "A user with this email already exists.", null);
        }

        var userCount = await db.Users.CountAsync(cancellationToken);
        var allowRegistration = await GetAllowRegistrationAsync(cancellationToken);
        if (userCount > 0 && !allowRegistration)
        {
            return (false, "Registration is currently disabled.", null);
        }

        var isFirstUser = userCount == 0;
        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            Email = email,
            PasswordHash = PasswordHasher.Hash(password),
            Role = isFirstUser ? "admin" : "user",
            DefaultNotifyMode = "once",
            DefaultExpiryMode = "7_days",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow
        };

        db.Users.Add(user);
        await db.SaveChangesAsync(cancellationToken);
        return (true, string.Empty, user);
    }

    public async Task<(bool Success, string Error, UserAccount? User)> LoginAsync(string email, string password, CancellationToken cancellationToken)
    {
        email = NormalizeEmail(email);
        var user = await db.Users.SingleOrDefaultAsync(x => x.Email == email, cancellationToken);
        if (user is null)
        {
            return (false, "Invalid credentials.", null);
        }

        if (!user.IsEnabled)
        {
            return (false, "This account is disabled.", null);
        }

        if (!PasswordHasher.Verify(password, user.PasswordHash))
        {
            return (false, "Invalid credentials.", null);
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
            PasswordHash = PasswordHasher.Hash(generatedPassword),
            Role = "admin",
            DefaultNotifyMode = "once",
            DefaultExpiryMode = "7_days",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow
        };

        db.Users.Add(user);
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
            await db.SaveChangesAsync(cancellationToken);
            return true;
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

    private static string NormalizeEmail(string value)
    {
        return (value ?? string.Empty).Trim().ToLowerInvariant();
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
}
