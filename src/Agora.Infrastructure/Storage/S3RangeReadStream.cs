using Amazon.S3;
using Amazon.S3.Model;

namespace Agora.Infrastructure.Storage;

/// <summary>
/// Seekable read-only view of an S3 object. Seeking is free; the first read after a seek opens one ranged GET
/// (position..end) that subsequent sequential reads consume. Reads at or beyond the end return 0 without a request.
/// This lets <c>Results.File(stream, enableRangeProcessing: true)</c> serve Range/If-Range requests unchanged.
/// </summary>
public sealed class S3RangeReadStream(IAmazonS3 s3, string bucket, string key, long length) : Stream
{
    private GetObjectResponse? _response;
    private long _position;
    private bool _disposed;

    public override bool CanRead => !_disposed;
    public override bool CanSeek => !_disposed;
    public override bool CanWrite => false;

    public override long Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return length;
        }
    }

    public override long Position
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _position;
        }
        set => Seek(value, SeekOrigin.Begin);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.Length == 0 || _position >= length)
        {
            return 0;
        }

        _response ??= await s3.GetObjectAsync(new GetObjectRequest
        {
            BucketName = bucket,
            Key = key,
            ByteRange = new ByteRange(_position, length - 1)
        }, cancellationToken);

        var read = await _response.ResponseStream.ReadAsync(buffer, cancellationToken);
        if (read == 0)
        {
            throw new EndOfStreamException($"Object '{key}' ended at {_position} of {length} bytes.");
        }

        _position += read;
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override long Seek(long offset, SeekOrigin origin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin))
        };
        ArgumentOutOfRangeException.ThrowIfNegative(target, nameof(offset));
        if (target != _position)
        {
            CloseResponse();
            _position = target;
        }

        return _position;
    }

    public override void Flush()
    {
    }

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CloseResponse();
        }

        _disposed = true;

        base.Dispose(disposing);
    }

    private void CloseResponse()
    {
        _response?.Dispose();
        _response = null;
    }
}
