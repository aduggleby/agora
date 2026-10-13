using System.Security.Cryptography;
using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class PasswordHasherTests
{
    [Fact]
    public void Hash_ProducesVersionedFormatThatVerifies()
    {
        var hash = PasswordHasher.Hash("correct horse");

        Assert.StartsWith($"v2${PasswordHasher.CurrentIterations}$", hash, StringComparison.Ordinal);
        Assert.True(PasswordHasher.Verify("correct horse", hash));
        Assert.False(PasswordHasher.Verify("wrong horse", hash));
        Assert.False(PasswordHasher.NeedsRehash(hash));
    }

    [Fact]
    public void Verify_AcceptsLegacyUnprefixedHashesAndFlagsThemForRehash()
    {
        var legacy = LegacyHash("old-password");

        Assert.True(PasswordHasher.Verify("old-password", legacy));
        Assert.False(PasswordHasher.Verify("other", legacy));
        Assert.True(PasswordHasher.NeedsRehash(legacy));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("v2$600000$bad")]
    [InlineData("v2$abc$QUJD$QUJD")]
    [InlineData("%%%:%%%")]
    public void Verify_ReturnsFalseForMalformedValues(string stored)
    {
        Assert.False(PasswordHasher.Verify("anything", stored));
    }

    [Fact]
    public void NeedsRehash_IsTrueForWeakerVersionedHashes()
    {
        var weaker = "v2$100000$" + Convert.ToBase64String(new byte[16]) + "$" + Convert.ToBase64String(new byte[32]);
        Assert.True(PasswordHasher.NeedsRehash(weaker));
        Assert.True(PasswordHasher.NeedsRehash(null));
    }

    internal static string LegacyHash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }
}
