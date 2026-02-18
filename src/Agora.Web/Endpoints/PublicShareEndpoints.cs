using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace Agora.Web.Endpoints;

public static class PublicShareEndpoints
{
    public static WebApplication MapPublicShareEndpoints(this WebApplication app)
    {
        app.MapGet("/s/{token}/background", async (ShareManager manager, IOptions<AgoraOptions> options, string token, ILoggerFactory loggerFactory, CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("Agora.DownloadPageBackground");
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null)
            {
                logger.LogWarning("Background request for token {Token} failed: share not found.", token);
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                logger.LogInformation("Background request for token {Token} denied: share expired or deleted.", token);
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var marker = share.BackgroundImageUrl ?? string.Empty;
            if (!marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogInformation(
                    "Background request for token {Token} failed: share has no internal marker. Marker: {Marker}",
                    token,
                    marker.Length == 0 ? "<empty>" : marker);
                return Results.NotFound();
            }

            var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
            var storageRoot = Path.GetFullPath(options.Value.StorageRoot);
            var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
            if (!absolutePath.StartsWith(storageRoot, StringComparison.Ordinal))
            {
                logger.LogWarning(
                    "Background request for token {Token} failed: resolved path escaped storage root. Marker: {Marker}",
                    token,
                    marker);
                return Results.NotFound();
            }

            if (!File.Exists(absolutePath))
            {
                logger.LogWarning(
                    "Background request for token {Token} failed: file missing at {Path}. Marker: {Marker}",
                    token,
                    absolutePath,
                    marker);
                return Results.NotFound();
            }

            logger.LogInformation(
                "Background request for token {Token} served file {Path}. Marker: {Marker}",
                token,
                absolutePath,
                marker);
            return Results.File(absolutePath, GuessImageContentType(Path.GetExtension(absolutePath)));
        });

        app.MapGet("/s/{token}/og-image", async (
            ShareManager manager,
            IOptions<AgoraOptions> options,
            OgImageGenerator ogGenerator,
            string token,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null) return Results.NotFound();

            string? bgPath = null;
            var marker = share.BackgroundImageUrl ?? string.Empty;
            if (marker.StartsWith("internal:", StringComparison.OrdinalIgnoreCase))
            {
                var relativePath = marker["internal:".Length..].TrimStart('/', '\\');
                var storageRoot = Path.GetFullPath(options.Value.StorageRoot);
                var absolutePath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
                if (absolutePath.StartsWith(storageRoot, StringComparison.Ordinal) && File.Exists(absolutePath))
                {
                    bgPath = absolutePath;
                }
            }

            var isExpired = ShareManager.IsExpired(share, DateTime.UtcNow);
            var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
                ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
                : $"{share.ZipSizeBytes / 1024.0:F0} KB";

            var imageBytes = await ogGenerator.GenerateShareOgImageAsync(
                backgroundImagePath: bgPath,
                backgroundColorHex: share.PageBackgroundColorHex,
                title: share.PageH1,
                subtitle: share.PageTitle,
                fileName: share.ZipDisplayName,
                fileCount: share.Files.Count,
                sizeDisplay: sizeDisplay,
                isExpired: isExpired);

            return Results.File(imageBytes, "image/png");
        });

        app.MapGet("/s/{token}/files", async (ShareManager manager, string token, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null)
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            return Results.Ok(share.Files.Select(file => new
            {
                file.Id,
                file.OriginalFilename,
                file.OriginalSizeBytes,
                file.RenderType,
                file.DetectedContentType,
                Url = $"/s/{Uri.EscapeDataString(token)}/files/{file.Id}"
            }));
        });

        app.MapGet("/s/{token}/files/{fileId:guid}", async (ShareManager manager, IShareContentStore contentStore, string token, Guid fileId, HttpRequest request, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null)
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var absolutePath = contentStore.ResolveAbsolutePath(file.StoredRelativePath);
            if (absolutePath is null || !File.Exists(absolutePath))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            request.HttpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";
            var asAttachment = request.Query["download"].ToString() == "1";
            var contentType = string.IsNullOrWhiteSpace(file.DetectedContentType) ? "application/octet-stream" : file.DetectedContentType;
            return asAttachment
                ? Results.File(absolutePath, contentType, file.OriginalFilename, enableRangeProcessing: true)
                : Results.File(absolutePath, contentType, enableRangeProcessing: true);
        }).RequireRateLimiting("DownloadEndpoints");

        app.MapGet("/s/{token}/gallery", (string token) => Results.Redirect($"/s/{token}"));

        app.MapGet("/s/{token}/download", (string token) =>
        {
            return Results.Redirect($"/s/{token}");
        }).RequireRateLimiting("DownloadEndpoints");

        app.MapPost("/s/{token}/download", async (ShareManager manager, IOptions<AgoraOptions> options, string token, HttpRequest request, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null)
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.Redirect($"/s/{token}");
            }

            if (!ShareManager.AllowsZipDownload(share))
            {
                return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=download_disabled");
            }

            var absolutePath = Path.Combine(options.Value.StorageRoot, share.ZipDiskPath);
            if (!File.Exists(absolutePath))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var requiresPassword = !string.IsNullOrWhiteSpace(share.DownloadPasswordHash);
            if (requiresPassword)
            {
                var form = request.HasFormContentType
                    ? await request.ReadFormAsync(ct)
                    : null;
                var downloadPassword = form?["downloadPassword"].ToString() ?? string.Empty;

                if (string.IsNullOrWhiteSpace(downloadPassword))
                {
                    return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=password_required");
                }

                var passwordHash = share.DownloadPasswordHash ?? string.Empty;
                if (!PasswordHasher.Verify(downloadPassword, passwordHash))
                {
                    return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
                }

                var tempRoot = Path.Combine(options.Value.StorageRoot, "downloads", "tmp");
                Directory.CreateDirectory(tempRoot);
                var decryptedPath = Path.Combine(tempRoot, $"{Guid.NewGuid():N}.zip");

                try
                {
                    await ZipEncryption.DecryptFileAsync(absolutePath, decryptedPath, downloadPassword, ct);
                }
                catch (CryptographicException)
                {
                    if (File.Exists(decryptedPath))
                    {
                        File.Delete(decryptedPath);
                    }

                    return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
                }

                var isAuthenticated = request.HttpContext.User.Identity?.IsAuthenticated == true;
                if (!isAuthenticated)
                {
                    var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    var userAgent = request.Headers.UserAgent.ToString();
                    await manager.RecordDownloadAsync(share, token, ip, userAgent, ct);
                }

                var decryptedStream = File.OpenRead(decryptedPath);
                request.HttpContext.Response.OnCompleted(() =>
                {
                    try
                    {
                        decryptedStream.Dispose();
                        if (File.Exists(decryptedPath))
                        {
                            File.Delete(decryptedPath);
                        }
                    }
                    catch
                    {
                    }

                    return Task.CompletedTask;
                });

                return Results.File(decryptedStream, "application/zip", share.ZipDisplayName);
            }

            var isAuthenticatedRequester = request.HttpContext.User.Identity?.IsAuthenticated == true;
            if (!isAuthenticatedRequester)
            {
                var ip = request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var userAgent = request.Headers.UserAgent.ToString();
                await manager.RecordDownloadAsync(share, token, ip, userAgent, ct);
            }

            var stream = File.OpenRead(absolutePath);
            return Results.File(stream, "application/zip", share.ZipDisplayName);
        }).RequireRateLimiting("DownloadEndpoints");

        return app;
    }

    private static string GuessImageContentType(string extension)
    {
        return (extension ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            _ => "application/octet-stream"
        };
    }
}
