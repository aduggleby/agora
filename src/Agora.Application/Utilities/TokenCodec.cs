using System.Security.Cryptography;
using System.Text;

namespace Agora.Application.Utilities;

public static class TokenCodec
{
    public static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string HashToken(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string TokenPrefix(string token)
    {
        return token.Length <= 8 ? token : token[..8];
    }
}
