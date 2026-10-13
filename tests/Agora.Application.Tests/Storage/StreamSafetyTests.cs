using System.Reflection;
using Agora.Infrastructure.Storage;
using Agora.Web.Services;
using Amazon.S3;

namespace Agora.Application.Tests.Storage;

/// <summary>Stream lifecycle and resource-bound checks: S3 stream disposal, FS handle metadata, OG background limits.</summary>
public sealed class StreamSafetyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Disposed_s3_stream_rejects_use_without_requests(bool disposeAsync)
    {
        var s3 = CallRecordingS3.Create();
        var stream = new S3RangeReadStream(s3, "bucket", "key", 100);
        if (disposeAsync)
        {
            await stream.DisposeAsync();
        }
        else
        {
            stream.Dispose();
        }

        Assert.False(stream.CanRead);
        Assert.False(stream.CanSeek);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => stream.ReadAsync(new byte[10]).AsTask());
        Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[10], 0, 10));
        Assert.Throws<ObjectDisposedException>(() => stream.Seek(5, SeekOrigin.Begin));
        Assert.Throws<ObjectDisposedException>(() => stream.Length);
        Assert.Empty(((CallRecordingS3)(object)s3).Calls);
    }

    [Fact]
    public async Task Filesystem_stream_survives_a_concurrent_unlink_and_releases_its_handle()
    {
        var root = Path.Combine(Path.GetTempPath(), "agora-fs-unlink", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FileSystemObjectStore(root);
            await store.PutBytesAsync("a/b.bin", [1, 2, 3, 4], null, CancellationToken.None);

            var opened = await store.OpenReadAsync("a/b.bin", CancellationToken.None);
            Assert.NotNull(opened);
            File.Delete(Path.Combine(root, "a", "b.bin"));

            Assert.Equal(4, opened.Info.Length);
            using var copy = new MemoryStream();
            await opened.Content.CopyToAsync(copy);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, copy.ToArray());
            await opened.Content.DisposeAsync();
            Assert.True(((FileStream)opened.Content).SafeFileHandle.IsClosed);
            Assert.Null(await store.OpenReadAsync("a/b.bin", CancellationToken.None));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Og_image_skips_oversized_background_without_reading_it()
    {
        var background = new CountingStream(OgImageGenerator.MaxBackgroundBytes + 1);

        var png = await CreateOgGenerator().GenerateShareOgImageAsync(background, null, "Title", null, "a.zip", 1, "1 KB", false);

        Assert.NotEmpty(png);
        Assert.Equal(0, background.BytesRead);
    }

    [Fact]
    public async Task Og_image_rejects_invalid_background_after_reading_only_its_header()
    {
        var background = new CountingStream(OgImageGenerator.MaxBackgroundBytes - 1);

        var png = await CreateOgGenerator().GenerateShareOgImageAsync(background, null, "Title", null, "a.zip", 1, "1 KB", false);

        Assert.NotEmpty(png);
        Assert.InRange(background.BytesRead, 1, 256 * 1024);
    }

    private static OgImageGenerator CreateOgGenerator() => new(Path.Combine(AppContext.BaseDirectory, "Fonts"));

    /// <summary>Seekable stream of zeros with a fixed length that counts the bytes actually read.</summary>
    private sealed class CountingStream(long length) : Stream
    {
        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get; set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = (int)Math.Clamp(length - Position, 0, count);
            Array.Clear(buffer, offset, read);
            Position += read;
            BytesRead += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => Position + offset,
            _ => length + offset
        };

        public override void Flush()
        {
        }

        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>IAmazonS3 stand-in that records every call and never talks to a server.</summary>
    public class CallRecordingS3 : DispatchProxy
    {
        public List<string> Calls { get; } = [];

        public static IAmazonS3 Create() => Create<IAmazonS3, CallRecordingS3>();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            Calls.Add(targetMethod?.Name ?? "?");
            throw new InvalidOperationException("No S3 calls expected.");
        }
    }
}

public sealed class S3TestEnvironmentTests
{
    [Fact]
    public async Task Only_docker_unavailability_is_a_skip_reason()
    {
        var reason = await S3TestEnvironment.StartContainerAsync(() =>
            throw new InvalidOperationException("outer", new Exception("Docker is either not running or misconfigured. Please ensure ...")));
        Assert.NotNull(reason);

        Assert.Null(await S3TestEnvironment.StartContainerAsync(() => Task.CompletedTask));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            S3TestEnvironment.StartContainerAsync(() => throw new InvalidOperationException("image pull failed")));
    }
}
