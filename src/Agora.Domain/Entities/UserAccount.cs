namespace Agora.Domain.Entities;

public sealed class UserAccount
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "user";
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; }
}
