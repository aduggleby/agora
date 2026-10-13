using System.Security.Cryptography;

namespace Agora.Application.Utilities;

/// <summary>
/// PBKDF2-HMAC-SHA256 password hashing with a versioned storage format.
/// v2 (current): "v2$iterations$base64(salt)$base64(hash)" with 600,000 iterations.
/// v1 (legacy, unprefixed): "base64(salt):base64(hash)" with 100,000 iterations.
/// Legacy hashes keep verifying; callers upgrade them via <see cref="NeedsRehash"/>.
/// </summary>
public static class PasswordHasher
{
    public const int CurrentIterations = 600_000;
    private const int LegacyIterations = 100_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const string CurrentVersionPrefix = "v2$";

    /// <summary>Test hook: observes the iteration count of every verification on the current async flow.</summary>
    internal static readonly AsyncLocal<Action<int>?> VerifyObserver = new();

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, CurrentIterations, HashAlgorithmName.SHA256, HashSize);
        return $"{CurrentVersionPrefix}{CurrentIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        return value.StartsWith(CurrentVersionPrefix, StringComparison.Ordinal)
            ? VerifyVersioned(password, value)
            : VerifyLegacy(password, value);
    }

    /// <summary>
    /// True when the stored value is not in the current format and should be re-hashed
    /// after a successful verification.
    /// </summary>
    public static bool NeedsRehash(string? value)
    {
        if (string.IsNullOrEmpty(value) || !value.StartsWith(CurrentVersionPrefix, StringComparison.Ordinal))
        {
            return true;
        }

        var parts = value.Split('$');
        return parts.Length != 4
            || !int.TryParse(parts[1], out var iterations)
            || iterations < CurrentIterations;
    }

    private static bool VerifyVersioned(string password, string value)
    {
        var parts = value.Split('$');
        if (parts.Length != 4 || !int.TryParse(parts[1], out var iterations) || iterations < 1)
        {
            return false;
        }

        return VerifyParts(password, parts[2], parts[3], iterations);
    }

    private static bool VerifyLegacy(string password, string value)
    {
        var parts = value.Split(':', 2);
        return parts.Length == 2 && VerifyParts(password, parts[0], parts[1], LegacyIterations);
    }

    private static bool VerifyParts(string password, string saltText, string hashText, int iterations)
    {
        if (!TryFromBase64(saltText, out var salt) || !TryFromBase64(hashText, out var expected) || expected.Length == 0)
        {
            return false;
        }

        VerifyObserver.Value?.Invoke(iterations);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool TryFromBase64(string text, out byte[] bytes)
    {
        var buffer = new byte[text.Length];
        if (Convert.TryFromBase64String(text, buffer, out var written))
        {
            bytes = buffer.AsSpan(0, written).ToArray();
            return true;
        }

        bytes = [];
        return false;
    }
}
