namespace Agora.Application.Utilities;

/// <summary>
/// Share tokens (the path segment of /s/{token}) are ASCII letters, digits, '-' and '_', 8 to 64 characters.
/// Generated tokens are 8 alphanumeric characters; custom ones are validated against the same rule.
/// </summary>
public static class ShareTokens
{
    public const int MinLength = 8;
    public const int MaxLength = 64;

    public static bool IsValid(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length < MinLength || token.Length > MaxLength)
        {
            return false;
        }

        foreach (var ch in token)
        {
            if (!char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '_')
            {
                return false;
            }
        }

        return true;
    }
}
