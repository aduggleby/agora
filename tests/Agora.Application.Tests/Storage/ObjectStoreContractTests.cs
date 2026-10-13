using System.Security.Cryptography;
using Agora.Application.Abstractions;
using Agora.Infrastructure.Storage;
using Amazon.S3;

namespace Agora.Application.Tests.Storage;

/// <summary>
/// Behaviour every <see cref="IObjectStore"/> must share. Runs against the file system, MinIO (Testcontainers) and,
/// opt-in, a real bucket (AGORA_S3_LIVE_*).
/// </summary>
public abstract class ObjectStoreContractTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    /// <summary>Creates a fresh scope; a small list page size exercises DeletePrefix paging on S3.</summary>
    protected abstract ObjectStoreScope CreateScope(int listPageSize = 1000);

    [SkippableFact]
    public async Task Bytes_round_trip_with_metadata_and_overwrite()
    {
        await using var scope = CreateScope();
        var key = scope.Key("docs/hello.txt");
        await scope.Store.PutBytesAsync(key, "hello"u8.ToArray(), "text/plain", Ct);
        await scope.Store.PutBytesAsync(key, "hello world"u8.ToArray(), "text/plain", Ct);

        var info = await scope.Store.GetInfoAsync(key, Ct);
        Assert.NotNull(info);
        Assert.Equal(11, info.Length);
        Assert.StartsWith("\"", info.ETag);
        Assert.EndsWith("\"", info.ETag);
        Assert.InRange(info.LastModified, DateTimeOffset.UtcNow.AddMinutes(-10), DateTimeOffset.UtcNow.AddMinutes(10));

        var opened = await scope.Store.OpenReadAsync(key, Ct);
        Assert.NotNull(opened);
        await using (opened.Content)
        {
            Assert.True(opened.Content.CanSeek);
            Assert.Equal(11, opened.Content.Length);
            Assert.Equal("hello world"u8.ToArray(), await ReadAllAsync(opened.Content));
        }
    }

    [SkippableFact]
    public async Task Large_file_round_trips_through_multipart_upload_and_download()
    {
        await using var scope = CreateScope();
        var temp = Path.Combine(Path.GetTempPath(), $"agora-objectstore-{Guid.NewGuid():N}");
        var downloaded = temp + ".down";
        try
        {
            // Above the 16 MB part size, so S3 uses a multipart upload.
            var content = RandomNumberGenerator.GetBytes((int)S3ObjectStore.MultipartPartSize + 4 * 1024 * 1024 + 123);
            await File.WriteAllBytesAsync(temp, content);
            var key = scope.Key("large/blob.bin");

            await scope.Store.PutFileAsync(key, temp, "application/octet-stream", Ct);
            Assert.Equal(content.Length, (await scope.Store.GetInfoAsync(key, Ct))!.Length);

            await scope.Store.DownloadToFileAsync(key, downloaded, Ct);
            Assert.Equal(SHA256.HashData(content), SHA256.HashData(await File.ReadAllBytesAsync(downloaded)));
        }
        finally
        {
            File.Delete(temp);
            File.Delete(downloaded);
        }
    }

    [SkippableFact]
    public async Task Missing_keys_are_reported_without_side_effects()
    {
        await using var scope = CreateScope();
        var key = scope.Key("missing/nothing.bin");

        Assert.Null(await scope.Store.GetInfoAsync(key, Ct));
        Assert.Null(await scope.Store.OpenReadAsync(key, Ct));
        await scope.Store.DeleteAsync(key, Ct);
        await scope.Store.DeletePrefixAsync(scope.Key("missing/"), Ct);
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            scope.Store.DownloadToFileAsync(key, Path.Combine(Path.GetTempPath(), $"agora-missing-{Guid.NewGuid():N}"), Ct));
        await Assert.ThrowsAsync<FileNotFoundException>(() => scope.Store.CopyAsync(key, scope.Key("missing/copy.bin"), Ct));
        Assert.Equal(0, await scope.CountAsync());
    }

    [SkippableFact]
    public async Task Stream_supports_seeking_forwards_backwards_and_eof()
    {
        await using var scope = CreateScope();
        var content = Enumerable.Range(0, 1000).Select(i => (byte)(i % 251)).ToArray();
        var key = scope.Key("range/data.bin");
        await scope.Store.PutBytesAsync(key, content, null, Ct);

        var opened = await scope.Store.OpenReadAsync(key, Ct);
        Assert.NotNull(opened);
        await using var stream = opened.Content;

        stream.Seek(400, SeekOrigin.Begin);
        Assert.Equal(content[400..500], await ReadExactlyAsync(stream, 100));
        Assert.Equal(500, stream.Position);

        stream.Position = 100;
        Assert.Equal(content[100..150], await ReadExactlyAsync(stream, 50));

        stream.Seek(-10, SeekOrigin.End);
        Assert.Equal(content[990..], await ReadAllAsync(stream));

        // At EOF reads return 0 without touching the object: deleting it first proves no request is made.
        await scope.Store.DeleteAsync(key, Ct);
        stream.Seek(0, SeekOrigin.End);
        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
        stream.Seek(5000, SeekOrigin.Begin);
        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
    }

    [SkippableFact]
    public async Task Empty_object_reads_as_zero_bytes()
    {
        await using var scope = CreateScope();
        var key = scope.Key("range/empty.bin");
        await scope.Store.PutBytesAsync(key, [], null, Ct);

        var opened = await scope.Store.OpenReadAsync(key, Ct);
        Assert.NotNull(opened);
        await using var stream = opened.Content;
        Assert.Equal(0, opened.Info.Length);
        Assert.Equal(0, stream.Length);
        await scope.Store.DeleteAsync(key, Ct);
        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
    }

    [SkippableFact]
    public async Task DeletePrefix_spans_multiple_pages_and_keeps_sibling_prefixes()
    {
        await using var scope = CreateScope(listPageSize: 3);
        for (var i = 0; i < 10; i++)
        {
            await scope.Store.PutBytesAsync(scope.Key($"del/{(i % 2 == 0 ? "a" : "b/c")}/{i}.txt"), [(byte)i], null, Ct);
        }

        await scope.Store.PutBytesAsync(scope.Key("del-sibling/keep.txt"), [1], null, Ct);
        await scope.Store.PutBytesAsync(scope.Key("delx"), [1], null, Ct);
        await scope.Store.PutBytesAsync(scope.Key("del.txt"), [1], null, Ct);

        await scope.Store.DeletePrefixAsync(scope.Key("del/"), Ct);

        Assert.Equal(0, await scope.CountAsync("del/"));
        Assert.Equal(3, await scope.CountAsync());
        Assert.NotNull(await scope.Store.GetInfoAsync(scope.Key("del-sibling/keep.txt"), Ct));
        Assert.NotNull(await scope.Store.GetInfoAsync(scope.Key("delx"), Ct));
        Assert.NotNull(await scope.Store.GetInfoAsync(scope.Key("del.txt"), Ct));
    }

    [SkippableFact]
    public async Task DeletePrefix_bulk_deletes_many_keys_in_one_batch()
    {
        await using var scope = CreateScope();
        await Task.WhenAll(Enumerable.Range(0, 60).Select(i =>
            scope.Store.PutBytesAsync(scope.Key($"bulk/{i / 10}/{i}.bin"), [(byte)i], null, Ct)));
        Assert.Equal(60, await scope.CountAsync("bulk/"));

        await scope.Store.DeletePrefixAsync(scope.Key("bulk/"), Ct);

        Assert.Equal(0, await scope.CountAsync());
    }

    [SkippableFact]
    public async Task Copy_duplicates_content_and_keeps_source()
    {
        await using var scope = CreateScope();
        var source = scope.Key("copy/source.jpg");
        var target = scope.Key("copy/nested/target.jpg");
        await scope.Store.PutBytesAsync(source, "image-bytes"u8.ToArray(), "image/jpeg", Ct);

        await scope.Store.CopyAsync(source, target, Ct);

        var copied = await scope.Store.OpenReadAsync(target, Ct);
        Assert.NotNull(copied);
        await using (copied.Content)
        {
            Assert.Equal("image-bytes"u8.ToArray(), await ReadAllAsync(copied.Content));
        }

        Assert.NotNull(await scope.Store.GetInfoAsync(source, Ct));
    }

    [SkippableTheory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("./x.txt")]
    [InlineData("shares/./x.txt")]
    [InlineData("shares/../x.txt")]
    [InlineData("../x.txt")]
    [InlineData("/shares/x.txt")]
    [InlineData("\\shares\\x.txt")]
    [InlineData("C:\\shares\\x.txt")]
    [InlineData("c:/shares/x.txt")]
    [InlineData("shares//x.txt")]
    [InlineData("shares/x/")]
    [InlineData("shares\\..\\x.txt")]
    public async Task Invalid_keys_are_rejected(string key)
    {
        await using var scope = CreateScope();
        await Assert.ThrowsAsync<ArgumentException>(() => scope.Store.PutBytesAsync(key, [1], null, Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => scope.Store.GetInfoAsync(key, Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => scope.Store.DeleteAsync(key, Ct));
    }

    [SkippableTheory]
    [InlineData("")]
    [InlineData("/")]
    [InlineData("./")]
    [InlineData("../")]
    [InlineData("shares/")]
    [InlineData("shares/./")]
    [InlineData("shares/../")]
    [InlineData("shares/x/../")]
    [InlineData("shares//x/")]
    [InlineData("/shares/x/")]
    [InlineData("C:/shares/x/")]
    [InlineData("shares/x")]
    public async Task Invalid_delete_prefixes_are_rejected_and_delete_nothing(string prefix)
    {
        await using var scope = CreateScope();
        await scope.Store.PutBytesAsync(scope.Key("guard/keep.txt"), [1], null, Ct);

        await Assert.ThrowsAsync<ArgumentException>(() => scope.Store.DeletePrefixAsync(prefix, Ct));

        Assert.Equal(1, await scope.CountAsync());
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        return buffer.ToArray();
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer);
        return buffer;
    }
}

public sealed class FileSystemObjectStoreContractTests : ObjectStoreContractTests
{
    protected override ObjectStoreScope CreateScope(int listPageSize = 1000) => ObjectStoreScope.FileSystem();
}

public sealed class MinioObjectStoreContractTests(MinioFixture fixture) : ObjectStoreContractTests, IClassFixture<MinioFixture>
{
    protected override ObjectStoreScope CreateScope(int listPageSize = 1000)
    {
        S3TestEnvironment.SkipOrFail(fixture.UnavailableReason);
        return ObjectStoreScope.S3(fixture.Client, MinioFixture.Bucket, "contract", listPageSize);
    }
}

/// <summary>
/// Opt-in smoke test against a real bucket (e.g. Hetzner): set AGORA_S3_LIVE_BUCKET, AGORA_S3_LIVE_ENDPOINT,
/// AGORA_S3_LIVE_REGION (optional AGORA_S3_LIVE_FORCE_PATH_STYLE, default false) and AWS_ACCESS_KEY_ID /
/// AWS_SECRET_ACCESS_KEY. Every test works under a unique agora-smoke/{guid}/ prefix and verifies it is empty after.
/// </summary>
public sealed class LiveS3ObjectStoreContractTests : ObjectStoreContractTests, IDisposable
{
    private readonly IAmazonS3? _client;
    private readonly string? _bucket = Environment.GetEnvironmentVariable("AGORA_S3_LIVE_BUCKET");

    public LiveS3ObjectStoreContractTests()
    {
        if (string.IsNullOrWhiteSpace(_bucket))
        {
            return;
        }

        _client = StorageSetup.CreateClient(new S3StorageOptions
        {
            ServiceUrl = Environment.GetEnvironmentVariable("AGORA_S3_LIVE_ENDPOINT") ?? string.Empty,
            Region = Environment.GetEnvironmentVariable("AGORA_S3_LIVE_REGION") ?? string.Empty,
            Bucket = _bucket,
            AccessKeyId = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID") ?? string.Empty,
            SecretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY") ?? string.Empty,
            ForcePathStyle = Environment.GetEnvironmentVariable("AGORA_S3_LIVE_FORCE_PATH_STYLE") == "true"
        });
    }

    protected override ObjectStoreScope CreateScope(int listPageSize = 1000)
    {
        Skip.If(_client is null, "Live S3 smoke test not configured (AGORA_S3_LIVE_BUCKET).");
        return ObjectStoreScope.S3(_client!, _bucket!, "agora-smoke", listPageSize);
    }

    public void Dispose() => _client?.Dispose();
}
