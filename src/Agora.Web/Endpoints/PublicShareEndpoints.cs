using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Services;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;


namespace Agora.Web.Endpoints;

public static class PublicShareEndpoints
{
    public static WebApplication MapPublicShareEndpoints(this WebApplication app)
    {
        app.MapGet("/s/{token}/background", async (ShareManager manager, IObjectStore objectStore, string token, HttpResponse response, ILoggerFactory loggerFactory, CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("Agora.DownloadPageBackground");
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                logger.LogWarning("Background request for share {TokenRef} failed: share not found.", LogSafe.Token(token));
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                logger.LogInformation("Background request for share {TokenRef} denied: share expired.", LogSafe.Token(token));
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var marker = share.BackgroundImageUrl ?? string.Empty;
            var key = ObjectKey.FromInternalMarker(marker);
            if (key is null)
            {
                logger.LogInformation(
                    "Background request for share {TokenRef} failed: share has no valid internal marker. Marker: {Marker}",
                    LogSafe.Token(token),
                    marker.Length == 0 ? "<empty>" : marker);
                return Results.NotFound();
            }

            var background = await objectStore.OpenReadAsync(key, ct);
            if (background is null)
            {
                logger.LogWarning("Background request for share {TokenRef} failed: object {Key} missing.", LogSafe.Token(token), key);
                return Results.NotFound();
            }

            logger.LogDebug("Background request for share {TokenRef} served object {Key}.", LogSafe.Token(token), key);
            return ObjectResults.UserContent(response, background, key);
        });

        // The PNG is rendered once per share and cached under previews/{shareId}/og.png (purged with the share's
        // other previews on deletion; page settings never change after creation). Password-protected shares get the
        // generic image so no title, file name or count leaks before the password is entered. Concurrent misses
        // render once (per-share lock), and a share deleted or expired while rendering gets its cache entry removed.
        app.MapGet("/s/{token}/og-image", async (
            ShareManager manager,
            IObjectStore objectStore,
            OgImageGenerator ogGenerator,
            KeyedAsyncLock locks,
            string token,
            HttpResponse response,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var cacheKey = SharePreviewPaths.OgImageKey(share.Id);
            var cached = await objectStore.OpenReadAsync(cacheKey, ct);
            if (cached is null)
            {
                using (await locks.LockAsync($"og:{share.Id:N}", ct))
                {
                    cached = await objectStore.OpenReadAsync(cacheKey, ct);
                    if (cached is null)
                    {
                        var imageBytes = await RenderOgImageAsync(share, objectStore, ogGenerator, ct);
                        await objectStore.PutBytesAsync(cacheKey, imageBytes, "image/png", ct);
                        if (!await manager.IsShareActiveAsync(share.Id, ct))
                        {
                            // Deleted or expired while rendering: the prefix purge may already have run, so remove our write.
                            await objectStore.DeleteAsync(cacheKey, ct);
                            return Results.NotFound();
                        }

                        cached = await objectStore.OpenReadAsync(cacheKey, ct);
                        if (cached is null)
                        {
                            ApplyOgImageHeaders(response);
                            return Results.File(imageBytes, "image/png");
                        }
                    }
                }
            }

            ApplyOgImageHeaders(response);
            return ObjectResults.UserContent(response, cached, "og.png");
        }).RequireRateLimiting(RateLimitSetup.DownloadEndpoints);

        app.MapGet("/s/{token}/files", async (ShareManager manager, string token, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
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
            if (!string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
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

        app.MapGet("/s/{token}/files/{fileId:guid}", async (ShareManager manager, IObjectStore objectStore, string token, Guid fileId, HttpRequest request, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
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
            if (!string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var stored = ObjectKey.TryNormalize(file.StoredRelativePath, out var key)
                ? await objectStore.OpenReadAsync(key, ct)
                : null;
            if (stored is null)
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            // Type and disposition come from the file name only (ContentTypePolicy); the stored
            // DetectedContentType may hold a client-declared value from older uploads.
            var asAttachment = request.Query["download"].ToString() == "1";
            return ObjectResults.UserContent(request.HttpContext.Response, stored, file.OriginalFilename, forceAttachment: asAttachment);
        }).RequireRateLimiting(RateLimitSetup.DownloadEndpoints);

        app.MapGet("/s/{token}/files/{fileId:guid}/preview", async (
            ShareManager manager,
            SharePreviewJobService previewJobService,
            string token,
            Guid fileId,
            HttpRequest request,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share) || !string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var payload = await previewJobService.LoadPreviewImageAsync(share, file, ct);
            request.HttpContext.Response.Headers["X-Agora-Preview-State"] = payload.State;
            ObjectResults.ApplyUserContentHeaders(request.HttpContext.Response);
            request.HttpContext.Response.Headers["Cache-Control"] = payload.IsCacheable
                ? "public,max-age=31536000,immutable"
                : "no-store";
            return Results.File(payload.Content, payload.ContentType);
        });

        app.MapGet("/s/{token}/files/{fileId:guid}/thumbnail", async (
            ShareManager manager,
            SharePreviewJobService previewJobService,
            string token,
            Guid fileId,
            HttpRequest request,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share) || !string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var payload = await previewJobService.LoadThumbnailAsync(share, file, ct);
            request.HttpContext.Response.Headers["X-Agora-Preview-State"] = payload.State;
            ObjectResults.ApplyUserContentHeaders(request.HttpContext.Response);
            request.HttpContext.Response.Headers["Cache-Control"] = payload.IsCacheable
                ? "public,max-age=31536000,immutable"
                : "no-store";
            return Results.File(payload.Content, payload.ContentType);
        });

        app.MapGet("/s/{token}/files/{fileId:guid}/preview-status", async (
            ShareManager manager,
            SharePreviewJobService previewJobService,
            string token,
            Guid fileId,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share) || !string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var availability = await previewJobService.GetAvailabilityAsync(share, file, ct);
            previewJobService.QueueGenerationIfIdle(share, file, availability);

            return Results.Ok(new
            {
                state = availability.State,
                reason = availability.Reason,
                previewUrl = $"/s/{Uri.EscapeDataString(token)}/files/{fileId}/preview?width=960&height=720",
                thumbnailUrl = $"/s/{Uri.EscapeDataString(token)}/files/{fileId}/thumbnail?width=420&height=300",
                retryUrl = $"/s/{Uri.EscapeDataString(token)}/files/{fileId}/preview/retry"
            });
        });

        app.MapGet("/s/{token}/files/{fileId:guid}/preview/retry", async (
            ShareManager manager,
            SharePreviewJobService previewJobService,
            string token,
            Guid fileId,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsPreview(share) || !string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }

            var file = share.Files.SingleOrDefault(x => x.Id == fileId);
            if (file is null)
            {
                return Results.NotFound();
            }

            var availability = await previewJobService.GetAvailabilityAsync(share, file, ct);
            if (string.Equals(availability.Reason, "unsupported_type", StringComparison.Ordinal))
            {
                return Results.Ok(new { state = "unavailable", reason = "unsupported_type" });
            }

            previewJobService.QueueGeneration(share.Id, file.Id);
            return Results.Accepted();
        }).RequireRateLimiting(RateLimitSetup.DownloadEndpoints);

        app.MapGet("/s/{token}/gallery", async (ShareManager manager, string token, CancellationToken ct) =>
            await RedirectToSharePageAsync(manager, token, ct));

        // Expired shares redirect to the page, which renders its expired view with status 410.
        app.MapGet("/s/{token}/download", async (ShareManager manager, string token, CancellationToken ct) =>
            await RedirectToSharePageAsync(manager, token, ct))
            .RequireRateLimiting(RateLimitSetup.DownloadEndpoints);

        app.MapPost("/s/{token}/download", async (ShareManager manager, IObjectStore objectStore, IOptions<AgoraOptions> options, string token, HttpRequest request, CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null || ShareManager.IsDeleted(share))
            {
                return Results.NotFound();
            }

            if (ShareManager.IsExpired(share, DateTime.UtcNow))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            if (!ShareManager.AllowsZipDownload(share))
            {
                return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=download_disabled");
            }

            if (!ObjectKey.TryNormalize(share.ZipDiskPath, out var archiveKey))
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var isAuthenticatedRequester = request.HttpContext.User.Identity?.IsAuthenticated == true;
            Task RecordDownloadAsync() => isAuthenticatedRequester
                ? Task.CompletedTask
                : manager.RecordDownloadAsync(share, token, ResolveRequesterIp(request), request.Headers.UserAgent.ToString(), ct);

            if (string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
                var archive = await objectStore.OpenReadAsync(archiveKey, ct);
                if (archive is null)
                {
                    return Results.StatusCode(StatusCodes.Status410Gone);
                }

                try
                {
                    await RecordDownloadAsync();
                }
                catch
                {
                    await archive.Content.DisposeAsync();
                    throw;
                }

                ObjectResults.ApplyUserContentHeaders(request.HttpContext.Response);
                return Results.File(archive.Content, "application/zip", share.ZipDisplayName);
            }

            // Password-protected: the stored object is not opened (not even its metadata) until the password
            // verifies, so a wrong guess costs a hash check and nothing else.
            var form = request.HasFormContentType
                ? await request.ReadFormAsync(ct)
                : null;
            var downloadPassword = form?["downloadPassword"].ToString() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(downloadPassword))
            {
                return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=password_required");
            }

            if (!PasswordHasher.Verify(downloadPassword, share.DownloadPasswordHash))
            {
                return Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
            }

            var encryptedArchive = await objectStore.OpenReadAsync(archiveKey, ct);
            if (encryptedArchive is null)
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            await using (encryptedArchive.Content)
            {
                return await EncryptedArchiveDownload.ServeAsync(
                        request.HttpContext,
                        encryptedArchive.Content,
                        downloadPassword,
                        options.Value.StorageRoot,
                        share.ZipDisplayName,
                        RecordDownloadAsync,
                        ct)
                    ?? Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
            }
        }).RequireRateLimiting(RateLimitSetup.DownloadEndpoints);

        return app;
    }

    private static async Task<IResult> RedirectToSharePageAsync(ShareManager manager, string token, CancellationToken ct)
    {
        var share = await manager.FindByTokenAsync(token, ct);
        if (share is null || ShareManager.IsDeleted(share))
        {
            return Results.NotFound();
        }

        return Results.Redirect($"/s/{Uri.EscapeDataString(token)}");
    }

    private static async Task<byte[]> RenderOgImageAsync(Domain.Entities.Share share, IObjectStore objectStore, OgImageGenerator ogGenerator, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
        {
            return await ogGenerator.GenerateDefaultOgImageAsync("Password-protected share", "Enter the password on the download page to open the files.");
        }

        // Streamed straight into the generator, which skips oversized or undecodable backgrounds.
        var backgroundKey = ObjectKey.FromInternalMarker(share.BackgroundImageUrl);
        var background = backgroundKey is null ? null : await objectStore.OpenReadAsync(backgroundKey, ct);
        await using var backgroundStream = background?.Content;

        var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
            ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
            : $"{share.ZipSizeBytes / 1024.0:F0} KB";

        return await ogGenerator.GenerateShareOgImageAsync(
            backgroundImage: backgroundStream,
            backgroundColorHex: share.PageBackgroundColorHex,
            title: share.PageH1,
            subtitle: share.PageTitle,
            fileName: share.ZipDisplayName,
            fileCount: share.Files.Count,
            sizeDisplay: sizeDisplay,
            isExpired: false);
    }

    private static void ApplyOgImageHeaders(HttpResponse response)
    {
        ObjectResults.ApplyUserContentHeaders(response);
        response.Headers.CacheControl = "public, max-age=3600";
    }

    /// <summary>
    /// The downloader's address as seen by the connection. Behind a trusted proxy (Agora:TrustedProxies) the
    /// forwarded-headers middleware has already replaced it with the client address; client-supplied headers are
    /// never read here.
    /// </summary>
    private static string ResolveRequesterIp(HttpRequest request)
    {
        var remote = request.HttpContext.Connection.RemoteIpAddress?.ToString();
        return IpAddressUtilities.TryNormalizeIp(remote, out var normalized) ? normalized : "unknown";
    }
}
