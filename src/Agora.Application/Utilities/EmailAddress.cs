namespace Agora.Application.Utilities;

/// <summary>
/// Canonical email form for storage and lookups (trimmed, lower-case), so comparisons do not depend on
/// database collation (SQL Server is case-insensitive by default, PostgreSQL is case-sensitive).
/// </summary>
public static class EmailAddress
{
    public static string Normalize(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant();

    public static string? NormalizeOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : Normalize(value);
}
