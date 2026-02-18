using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Agora.Application.Utilities;

public static class ZipEncryption
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("AGZ1");
    private const byte Version = 1;
    private const int SaltSize = 16;
    private const int NoncePrefixSize = 8;
    private const int NonceSize = 12;
    private const int KeySize = 32;
    private const int TagSize = 16;
    private const int DefaultChunkSize = 64 * 1024;
    private const int Pbkdf2Iterations = 600_000;

    public static async Task EncryptFileAsync(string inputPath, string encryptedOutputPath, string password, CancellationToken cancellationToken)
    {
        await using var input = File.OpenRead(inputPath);
        await using var output = File.Create(encryptedOutputPath);
        await EncryptAsync(input, output, password, cancellationToken);
    }

    public static async Task DecryptFileAsync(string encryptedInputPath, string outputPath, string password, CancellationToken cancellationToken)
    {
        await using var input = File.OpenRead(encryptedInputPath);
        await using var output = File.Create(outputPath);
        await DecryptAsync(input, output, password, cancellationToken);
    }

    public static async Task EncryptAsync(Stream input, Stream output, string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var noncePrefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);

        await WriteHeaderAsync(output, salt, noncePrefix, cancellationToken);

        using var aes = new AesGcm(key, TagSize);
        var plainBuffer = new byte[DefaultChunkSize];
        var cipherAndTagBuffer = new byte[DefaultChunkSize + TagSize];
        var nonce = new byte[NonceSize];
        uint chunkCounter = 0;

        while (true)
        {
            var read = await input.ReadAsync(plainBuffer.AsMemory(0, plainBuffer.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (chunkCounter == uint.MaxValue)
            {
                throw new InvalidOperationException("Encrypted payload is too large.");
            }

            BuildNonce(noncePrefix, chunkCounter, nonce);
            var plain = plainBuffer.AsSpan(0, read);
            var cipher = cipherAndTagBuffer.AsSpan(0, read);
            var tag = cipherAndTagBuffer.AsSpan(read, TagSize);
            aes.Encrypt(nonce, plain, cipher, tag);

            await WriteInt32Async(output, read, cancellationToken);
            await output.WriteAsync(cipherAndTagBuffer.AsMemory(0, read + TagSize), cancellationToken);
            chunkCounter += 1;
        }
    }

    public static async Task DecryptAsync(Stream input, Stream output, string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Password is required.", nameof(password));
        }

        var header = await ReadHeaderAsync(input, cancellationToken);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, header.Salt, header.Iterations, HashAlgorithmName.SHA256, KeySize);
        using var aes = new AesGcm(key, TagSize);

        var plainBuffer = new byte[header.ChunkSize];
        var cipherAndTagBuffer = new byte[header.ChunkSize + TagSize];
        var nonce = new byte[NonceSize];
        uint chunkCounter = 0;

        while (true)
        {
            var plainLength = await TryReadInt32Async(input, cancellationToken);
            if (plainLength is null)
            {
                break;
            }

            if (plainLength <= 0 || plainLength > header.ChunkSize)
            {
                throw new CryptographicException("Encrypted file is invalid.");
            }

            if (chunkCounter == uint.MaxValue)
            {
                throw new CryptographicException("Encrypted file is invalid.");
            }

            var cipherLength = plainLength.Value;
            await ReadExactlyAsync(input, cipherAndTagBuffer.AsMemory(0, cipherLength + TagSize), cancellationToken);

            BuildNonce(header.NoncePrefix, chunkCounter, nonce);
            var cipher = cipherAndTagBuffer.AsSpan(0, cipherLength);
            var tag = cipherAndTagBuffer.AsSpan(cipherLength, TagSize);
            var plain = plainBuffer.AsSpan(0, plainLength.Value);
            aes.Decrypt(nonce, cipher, tag, plain);
            await output.WriteAsync(plainBuffer.AsMemory(0, plainLength.Value), cancellationToken);

            chunkCounter += 1;
        }
    }

    private static async Task WriteHeaderAsync(Stream output, byte[] salt, byte[] noncePrefix, CancellationToken cancellationToken)
    {
        await output.WriteAsync(Magic, cancellationToken);
        await output.WriteAsync(new byte[] { Version }, cancellationToken);
        await WriteInt32Async(output, Pbkdf2Iterations, cancellationToken);
        await WriteInt32Async(output, DefaultChunkSize, cancellationToken);
        await output.WriteAsync(salt, cancellationToken);
        await output.WriteAsync(noncePrefix, cancellationToken);
    }

    private static async Task<(int Iterations, int ChunkSize, byte[] Salt, byte[] NoncePrefix)> ReadHeaderAsync(Stream input, CancellationToken cancellationToken)
    {
        var magic = new byte[Magic.Length];
        await ReadExactlyAsync(input, magic, cancellationToken);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw new CryptographicException("Encrypted file format is invalid.");
        }

        var version = new byte[1];
        await ReadExactlyAsync(input, version, cancellationToken);
        if (version[0] != Version)
        {
            throw new CryptographicException("Encrypted file format is unsupported.");
        }

        var iterations = await ReadInt32Async(input, cancellationToken);
        if (iterations < 100_000)
        {
            throw new CryptographicException("Encrypted file format is invalid.");
        }

        var chunkSize = await ReadInt32Async(input, cancellationToken);
        if (chunkSize < 1024 || chunkSize > (1024 * 1024))
        {
            throw new CryptographicException("Encrypted file format is invalid.");
        }

        var salt = new byte[SaltSize];
        await ReadExactlyAsync(input, salt, cancellationToken);

        var noncePrefix = new byte[NoncePrefixSize];
        await ReadExactlyAsync(input, noncePrefix, cancellationToken);

        return (iterations, chunkSize, salt, noncePrefix);
    }

    private static void BuildNonce(byte[] noncePrefix, uint chunkCounter, byte[] nonceDestination)
    {
        noncePrefix.CopyTo(nonceDestination, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonceDestination.AsSpan(NoncePrefixSize), chunkCounter);
    }

    private static async Task WriteInt32Async(Stream stream, int value, CancellationToken cancellationToken)
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, value);
        await stream.WriteAsync(buffer, cancellationToken);
    }

    private static async Task<int> ReadInt32Async(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[4];
        await ReadExactlyAsync(stream, buffer, cancellationToken);
        return BinaryPrimitives.ReadInt32LittleEndian(buffer);
    }

    private static async Task<int?> TryReadInt32Async(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[4];
        var read = await stream.ReadAsync(buffer.AsMemory(0, 4), cancellationToken);
        if (read == 0)
        {
            return null;
        }

        if (read < 4)
        {
            await ReadExactlyAsync(stream, buffer.AsMemory(read, 4 - read), cancellationToken);
        }

        return BinaryPrimitives.ReadInt32LittleEndian(buffer);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < destination.Length)
        {
            var read = await stream.ReadAsync(destination[totalRead..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            totalRead += read;
        }
    }
}
