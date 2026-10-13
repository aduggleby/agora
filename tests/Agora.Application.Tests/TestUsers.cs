using Agora.Application.Utilities;
using Agora.Domain.Entities;

namespace Agora.Application.Tests;

/// <summary>Minimal enabled, confirmed account rows for tests that create shares (creation requires a live owner).</summary>
internal static class TestUsers
{
    public static UserAccount Seed(Guid id, string email) => new()
    {
        Id = id,
        Email = EmailAddress.Normalize(email),
        EmailConfirmed = true,
        PasswordHash = "x:y",
        SecurityStamp = SecurityStamps.New(),
        Role = "user",
        IsEnabled = true,
        UploadToken = Guid.NewGuid().ToString("N")[..8],
        CreatedAtUtc = DateTime.UtcNow
    };
}
