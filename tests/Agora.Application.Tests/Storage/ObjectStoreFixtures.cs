using Agora.Application.Abstractions;
using Agora.Infrastructure.Storage;
using Amazon.S3;
using Amazon.S3.Model;
using Testcontainers.Minio;

namespace Agora.Application.Tests.Storage;

/// <summary>
/// One MinIO container (Testcontainers) per test class. Skipped without Docker; failed instead when
/// AGORA_REQUIRE_S3_TESTS=1.
/// </summary>
public sealed class MinioFixture : IAsyncLifetime
{
    public const string Image = "quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z";
    public const string Bucket = "agora-tests";
    private MinioContainer? _container;

    public string? UnavailableReason { get; private set; }
    public IAmazonS3 Client { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        // Only a missing Docker skips; client or bucket setup failures fail the tests.
        UnavailableReason = await S3TestEnvironment.StartContainerAsync(async () =>
        {
            _container = new MinioBuilder(Image).Build();
            await _container.StartAsync();
        });
        if (UnavailableReason is not null)
        {
            return;
        }

        Client = StorageSetup.CreateClient(new S3StorageOptions
        {
            ServiceUrl = _container!.GetConnectionString(),
            Region = "us-east-1",
            Bucket = Bucket,
            AccessKeyId = _container.GetAccessKey(),
            SecretAccessKey = _container.GetSecretKey(),
            ForcePathStyle = true
        });
        await Client.PutBucketAsync(Bucket);
    }

    public S3ObjectStore CreateStore(int listPageSize = 1000)
    {
        S3TestEnvironment.SkipOrFail(UnavailableReason);
        return new S3ObjectStore(Client, Bucket, listPageSize);
    }

    public async Task DisposeAsync()
    {
        Client?.Dispose();
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}

public static class S3TestEnvironment
{
    private const string DockerUnavailableMessage = "Docker is either not running or misconfigured";

    /// <summary>Starts a container; returns a skip reason only when Docker itself is unavailable, rethrows anything else.</summary>
    public static async Task<string?> StartContainerAsync(Func<Task> start)
    {
        try
        {
            await start();
            return null;
        }
        catch (Exception ex) when (IsDockerUnavailable(ex))
        {
            return $"MinIO test container unavailable (Docker required): {ex.Message}";
        }
    }

    public static bool IsDockerUnavailable(Exception ex)
    {
        for (Exception? current = ex; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains(DockerUnavailableMessage, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static void SkipOrFail(string? unavailableReason)
    {
        if (unavailableReason is not null && Environment.GetEnvironmentVariable("AGORA_REQUIRE_S3_TESTS") == "1")
        {
            throw new InvalidOperationException($"AGORA_REQUIRE_S3_TESTS=1 but {unavailableReason}");
        }

        Skip.If(unavailableReason is not null, unavailableReason);
    }

    public static async Task<int> CountAsync(IAmazonS3 client, string bucket, string prefix)
    {
        var count = 0;
        var request = new ListObjectsV2Request { BucketName = bucket, Prefix = prefix };
        ListObjectsV2Response page;
        do
        {
            page = await client.ListObjectsV2Async(request);
            count += page.S3Objects?.Count ?? 0;
            request.ContinuationToken = page.NextContinuationToken;
        }
        while (page.IsTruncated == true);

        return count;
    }
}

/// <summary>A store plus a unique key scope (all test keys live under it) and a way to count what is left.</summary>
public sealed class ObjectStoreScope(IObjectStore store, string scope, Func<string, Task<int>> countUnder, Func<Task>? dispose = null) : IAsyncDisposable
{
    public IObjectStore Store { get; } = store;
    public string Scope { get; } = scope;

    public string Key(string relative) => $"{Scope}/{relative}";

    public Task<int> CountAsync(string relativePrefix = "") => countUnder($"{Scope}/{relativePrefix}");

    public async ValueTask DisposeAsync()
    {
        await Store.DeletePrefixAsync(Scope + "/", CancellationToken.None);
        Assert.Equal(0, await CountAsync());
        if (dispose is not null)
        {
            await dispose();
        }
    }

    public static ObjectStoreScope FileSystem()
    {
        var root = Path.Combine(Path.GetTempPath(), "agora-objectstore-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return new ObjectStoreScope(
            // Trailing separator on purpose: StorageRoot values like "/app/data/uploads/" must keep working.
            new FileSystemObjectStore(root + Path.DirectorySeparatorChar),
            "t/scope",
            prefix =>
            {
                var directory = Path.Combine(root, prefix.TrimEnd('/'));
                return Task.FromResult(Directory.Exists(directory) ? Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories).Count() : 0);
            },
            () =>
            {
                Directory.Delete(root, recursive: true);
                return Task.CompletedTask;
            });
    }

    public static ObjectStoreScope S3(IAmazonS3 client, string bucket, string scopeRoot, int listPageSize = 1000) =>
        new(
            new S3ObjectStore(client, bucket, listPageSize),
            $"{scopeRoot}/{Guid.NewGuid():N}",
            prefix => S3TestEnvironment.CountAsync(client, bucket, prefix));
}
