using System.Security.Cryptography;
using System.Text;

namespace Agora.Application.Utilities;

/// <summary>
/// Helpers for putting secrets into log lines without exposing them.
/// </summary>
public static class LogSafe
{
    private const string Empty = "(none)";
    private const int ReferenceLength = 12;

    /// <summary>
    /// Returns a stable, non-reversible reference for a token (share, upload, confirmation, ...)
    /// so log lines can be correlated without containing the token itself.
    /// </summary>
    public static string Token(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return Empty;
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return $"tok:{Convert.ToHexStringLower(digest)[..ReferenceLength]}";
    }
}
