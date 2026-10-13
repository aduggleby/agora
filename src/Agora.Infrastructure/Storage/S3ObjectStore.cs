using System.Net;
using Agora.Application.Abstractions;
using Agora.Application.Utilities;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.S3.Transfer;

namespace Agora.Infrastructure.Storage;

/// <summary>
/// S3-compatible object store (Hetzner Object Storage in production, MinIO in tests).
/// </summary>
public sealed class S3ObjectStore(IAmazonS3 s3, string bucket, int listPageSize = 1000) : IObjectStore
{
    public const long MultipartPartSize = 16L * 1024 * 1024;

    public async Task PutFileAsync(string key, string localPath, string? contentType, CancellationToken ct)
    {
        using var transfer = new TransferUtility(s3);
        await transfer.UploadAsync(new TransferUtilityUploadRequest
        {
            BucketName = bucket,
            Key = ObjectKey.Normalize(key),
            FilePath = localPath,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
            PartSize = MultipartPartSize
        }, ct);
    }

    public async Task PutBytesAsync(string key, byte[] content, string? contentType, CancellationToken ct)
    {
        using var body = new MemoryStream(content, writable: false);
        await s3.PutObjectAsync(new PutObjectRequest
        {
            BucketName = bucket,
            Key = ObjectKey.Normalize(key),
            InputStream = body,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType
        }, ct);
    }

    public async Task<ObjectInfo?> GetInfoAsync(string key, CancellationToken ct)
    {
        try
        {
            var metadata = await s3.GetObjectMetadataAsync(bucket, ObjectKey.Normalize(key), ct);
            return new ObjectInfo(
                metadata.ContentLength,
                metadata.LastModified is { } lastModified ? new DateTimeOffset(lastModified.ToUniversalTime()) : DateTimeOffset.UnixEpoch,
                QuoteETag(metadata.ETag));
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
    }

    public async Task<ObjectStream?> OpenReadAsync(string key, CancellationToken ct)
    {
        var normalized = ObjectKey.Normalize(key);
        var info = await GetInfoAsync(normalized, ct);
        return info is null ? null : new ObjectStream(new S3RangeReadStream(s3, bucket, normalized, info.Length), info);
    }

    public async Task DownloadToFileAsync(string key, string localPath, CancellationToken ct)
    {
        try
        {
            using var response = await s3.GetObjectAsync(bucket, ObjectKey.Normalize(key), ct);
            await using var target = File.Create(localPath);
            await response.ResponseStream.CopyToAsync(target, ct);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            throw new FileNotFoundException("Object not found.", key, ex);
        }
    }

    public Task DeleteAsync(string key, CancellationToken ct) =>
        s3.DeleteObjectAsync(bucket, ObjectKey.Normalize(key), ct);

    public async Task DeletePrefixAsync(string prefix, CancellationToken ct)
    {
        var request = new ListObjectsV2Request { BucketName = bucket, Prefix = ObjectKey.NormalizePrefix(prefix), MaxKeys = listPageSize };
        ListObjectsV2Response page;
        do
        {
            page = await s3.ListObjectsV2Async(request, ct);
            var keys = page.S3Objects ?? [];
            if (keys.Count > 0)
            {
                var result = await s3.DeleteObjectsAsync(new DeleteObjectsRequest
                {
                    BucketName = bucket,
                    Objects = keys.Select(x => new KeyVersion { Key = x.Key }).ToList(),
                    Quiet = true
                }, ct);
                if (result.DeleteErrors is { Count: > 0 } errors)
                {
                    throw new IOException($"Failed to delete {errors.Count} object(s) under '{prefix}': {errors[0].Code} {errors[0].Message}");
                }
            }

            // Deleted keys disappear from the listing, but follow the continuation token in case the store
            // returns a stable snapshot.
            request.ContinuationToken = page.NextContinuationToken;
        }
        while (page.IsTruncated == true);
    }

    public async Task CopyAsync(string sourceKey, string destinationKey, CancellationToken ct)
    {
        try
        {
            await s3.CopyObjectAsync(bucket, ObjectKey.Normalize(sourceKey), bucket, ObjectKey.Normalize(destinationKey), ct);
        }
        catch (AmazonS3Exception ex) when (ex.StatusCode == HttpStatusCode.NotFound)
        {
            throw new FileNotFoundException("Object not found.", sourceKey, ex);
        }
    }

    /// <summary>Readiness probe: lists at most one key, which fails when the bucket or credentials are wrong.</summary>
    public Task PingAsync(CancellationToken ct) =>
        s3.ListObjectsV2Async(new ListObjectsV2Request { BucketName = bucket, MaxKeys = 1 }, ct);

    private static string QuoteETag(string? etag)
    {
        var value = (etag ?? string.Empty).Trim('"');
        return $"\"{(value.Length == 0 ? "0" : value)}\"";
    }
}
