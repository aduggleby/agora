namespace Agora.Domain.Entities;

public sealed class UserAccount
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public bool EmailConfirmed { get; set; }
    public DateTime? EmailConfirmedAtUtc { get; set; }
    public string? EmailConfirmationTokenHash { get; set; }
    public DateTime? EmailConfirmationTokenExpiresAtUtc { get; set; }
    public string? PendingEmail { get; set; }
    public string? PendingEmailTokenHash { get; set; }
    public DateTime? PendingEmailTokenExpiresAtUtc { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public string? PendingPasswordHash { get; set; }
    public string? PendingPasswordTokenHash { get; set; }
    public DateTime? PendingPasswordTokenExpiresAtUtc { get; set; }
    public string? PasswordResetTokenHash { get; set; }
    public DateTime? PasswordResetTokenExpiresAtUtc { get; set; }
    public string Role { get; set; } = "user";
    public string DefaultNotifyMode { get; set; } = "once";
    public string DefaultExpiryMode { get; set; } = "7_days";
    public bool IsEnabled { get; set; } = true;
    /// <summary>
    /// Random value embedded in every sign-in cookie and compared on revalidation. Rotating it signs the user out of
    /// all sessions; empty means the row predates stamps and gets one at the next sign-in.
    /// </summary>
    public string SecurityStamp { get; set; } = string.Empty;
    public string UploadToken { get; set; } = string.Empty;
    public DateTime? UploadTokenUpdatedAtUtc { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LastFailedLoginAtUtc { get; set; }
    public DateTime? LockoutEndUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
}
