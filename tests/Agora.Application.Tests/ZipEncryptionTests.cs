using System.Security.Cryptography;
using System.Text;
using Agora.Application.Utilities;

namespace Agora.Application.Tests;

public sealed class ZipEncryptionTests
{
    [Fact]
    public async Task EncryptAndDecryptRoundTripsPayload()
    {
        var plain = Encoding.UTF8.GetBytes(string.Join("", Enumerable.Repeat("agora-", 20_000)));
        await using var input = new MemoryStream(plain);
        await using var encrypted = new MemoryStream();

        await ZipEncryption.EncryptAsync(input, encrypted, "correct horse battery staple", CancellationToken.None);
        encrypted.Position = 0;

        await using var output = new MemoryStream();
        await ZipEncryption.DecryptAsync(encrypted, output, "correct horse battery staple", CancellationToken.None);

        Assert.Equal(plain, output.ToArray());
    }

    [Fact]
    public async Task DecryptWithWrongPasswordThrows()
    {
        var plain = Encoding.UTF8.GetBytes("short payload");
        await using var input = new MemoryStream(plain);
        await using var encrypted = new MemoryStream();

        await ZipEncryption.EncryptAsync(input, encrypted, "right-password", CancellationToken.None);
        encrypted.Position = 0;

        await using var output = new MemoryStream();
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            ZipEncryption.DecryptAsync(encrypted, output, "wrong-password", CancellationToken.None));
    }
}
