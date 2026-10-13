namespace Agora.Application.Utilities;

/// <summary>Length rules for newly assigned account passwords (existing passwords of any length keep verifying).</summary>
public static class PasswordPolicy
{
    public const int MinLength = 8;
    public const int MaxLength = 128;
    public const string LengthError = "Password must be 8-128 characters.";

    public static bool IsAcceptableLength(string? password) =>
        password is not null && password.Length >= MinLength && password.Length <= MaxLength;
}
