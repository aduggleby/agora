using System.Security.Cryptography;

namespace Agora.Application.Utilities;

/// <summary>
/// Creates the per-user security stamp that is embedded in sign-in cookies. A new stamp invalidates every existing
/// session of that user at its next revalidation.
/// </summary>
public static class SecurityStamps
{
    public static string New() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
}
