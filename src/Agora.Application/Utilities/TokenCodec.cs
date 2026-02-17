using System.Security.Cryptography;
using System.Text;

namespace Agora.Application.Utilities;

public static class TokenCodec
{
    private const string AlphanumericCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string GenerateAlphanumericToken(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Token length must be positive.");
        }

        var buffer = new char[length];
        for (var i = 0; i < length; i += 1)
        {
            buffer[i] = AlphanumericCharacters[RandomNumberGenerator.GetInt32(AlphanumericCharacters.Length)];
        }

        return new string(buffer);
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
