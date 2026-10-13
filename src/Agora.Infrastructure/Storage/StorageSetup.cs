using Agora.Application.Abstractions;
using Amazon.Runtime;
using Amazon.S3;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Agora.Infrastructure.Storage;

public enum StorageProvider
{
    FileSystem,
    S3
}

public sealed class S3StorageOptions
{
    public string ServiceUrl { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string Bucket { get; set; } = string.Empty;
    public string AccessKeyId { get; set; } = string.Empty;
    public string SecretAccessKey { get; set; } = string.Empty;

    /// <summary>False (virtual-hosted style) for Hetzner; true for MinIO.</summary>
    public bool ForcePathStyle { get; set; }
}

/// <summary>
/// Selects the durable object store: <c>Storage:Provider=FileSystem</c> (default, rooted at StorageRoot) or <c>S3</c>
/// with <c>Storage:S3:*</c>. Invalid configuration fails at startup.
/// </summary>
public static class StorageSetup
{
    public const string ProviderKey = "Storage:Provider";
    public const string S3Section = "Storage:S3";

    public static StorageProvider ParseProvider(string? value)
    {
        return (value ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "" or "filesystem" => StorageProvider.FileSystem,
            "s3" => StorageProvider.S3,
            _ => throw new InvalidOperationException($"Unsupported {ProviderKey} '{value}'. Use 'FileSystem' or 'S3'.")
        };
    }

    public static S3StorageOptions ReadS3Options(IConfiguration configuration)
    {
        var section = configuration.GetSection(S3Section);
        var options = new S3StorageOptions
        {
            ServiceUrl = section["ServiceUrl"]?.Trim() ?? string.Empty,
            Region = section["Region"]?.Trim() ?? string.Empty,
            Bucket = section["Bucket"]?.Trim() ?? string.Empty,
            AccessKeyId = section["AccessKeyId"]?.Trim() ?? string.Empty,
            SecretAccessKey = section["SecretAccessKey"] ?? string.Empty,
            ForcePathStyle = string.IsNullOrWhiteSpace(section["ForcePathStyle"])
                ? false
                : bool.TryParse(section["ForcePathStyle"], out var forcePathStyle)
                    ? forcePathStyle
                    : throw new InvalidOperationException($"{S3Section}:ForcePathStyle must be 'true' or 'false'.")
        };
        var missing = new[]
        {
            (nameof(options.ServiceUrl), options.ServiceUrl),
            (nameof(options.Region), options.Region),
            (nameof(options.Bucket), options.Bucket),
            (nameof(options.AccessKeyId), options.AccessKeyId),
            (nameof(options.SecretAccessKey), options.SecretAccessKey)
        }.Where(x => string.IsNullOrWhiteSpace(x.Item2)).Select(x => $"{S3Section}:{x.Item1}").ToList();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException($"{ProviderKey}=S3 requires {string.Join(", ", missing)}.");
        }

        if (!Uri.TryCreate(options.ServiceUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException($"{S3Section}:ServiceUrl must be an absolute http(s) URL.");
        }

        return options;
    }

    public static AmazonS3Client CreateClient(S3StorageOptions options) =>
        new(new BasicAWSCredentials(options.AccessKeyId, options.SecretAccessKey), new AmazonS3Config
        {
            ServiceURL = options.ServiceUrl,
            AuthenticationRegion = options.Region,
            ForcePathStyle = options.ForcePathStyle,
            // Hetzner (Ceph) and older MinIO reject the SDK's default CRC trailers on every request.
            RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED,
            ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED,
            Timeout = TimeSpan.FromMinutes(5),
            MaxErrorRetry = 3
        });

    public static StorageProvider AddAgoraObjectStore(this IServiceCollection services, IConfiguration configuration, string storageRoot)
    {
        var provider = ParseProvider(configuration[ProviderKey]);
        if (provider == StorageProvider.S3)
        {
            var options = ReadS3Options(configuration);
            services.AddSingleton<IAmazonS3>(_ => CreateClient(options));
            services.AddSingleton(sp => new S3ObjectStore(sp.GetRequiredService<IAmazonS3>(), options.Bucket));
            services.AddSingleton<IObjectStore>(sp => sp.GetRequiredService<S3ObjectStore>());
        }
        else
        {
            services.AddSingleton<IObjectStore>(new FileSystemObjectStore(storageRoot));
        }

        return provider;
    }
}
