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
        app.MapGet("/s/{token}/background", async (ShareManager manager, IObjectStore objectStore, string token, HttpResponse response, ILoggerFactory loggerFactory, CancellationToken ct) =>
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
            var key = ObjectKey.FromInternalMarker(marker);
            if (key is null)
            {
                logger.LogInformation(
                    "Background request for token {Token} failed: share has no valid internal marker. Marker: {Marker}",
                    token,
                    marker.Length == 0 ? "<empty>" : marker);
                return Results.NotFound();
            }

            var background = await objectStore.OpenReadAsync(key, ct);
            if (background is null)
            {
                logger.LogWarning("Background request for token {Token} failed: object {Key} missing.", token, key);
                return Results.NotFound();
            }

            logger.LogInformation("Background request for token {Token} served object {Key}.", token, key);
            return ObjectResults.UserContent(response, background, key);
        });

        app.MapGet("/s/{token}/og-image", async (
            ShareManager manager,
            IObjectStore objectStore,
            OgImageGenerator ogGenerator,
            string token,
            HttpResponse response,
            CancellationToken ct) =>
        {
            var share = await manager.FindByTokenAsync(token, ct);
            if (share is null) return Results.NotFound();

            // Streamed straight into the generator, which skips oversized or undecodable backgrounds.
            var backgroundKey = ObjectKey.FromInternalMarker(share.BackgroundImageUrl);
            var background = backgroundKey is null ? null : await objectStore.OpenReadAsync(backgroundKey, ct);
            await using var backgroundStream = background?.Content;

            var isExpired = ShareManager.IsExpired(share, DateTime.UtcNow);
            var sizeDisplay = share.ZipSizeBytes >= 1024 * 1024
                ? $"{share.ZipSizeBytes / (1024.0 * 1024.0):F1} MB"
                : $"{share.ZipSizeBytes / 1024.0:F0} KB";

            var imageBytes = await ogGenerator.GenerateShareOgImageAsync(
                backgroundImage: backgroundStream,
                backgroundColorHex: share.PageBackgroundColorHex,
                title: share.PageH1,
                subtitle: share.PageTitle,
                fileName: share.ZipDisplayName,
                fileCount: share.Files.Count,
                sizeDisplay: sizeDisplay,
                isExpired: isExpired);

            ObjectResults.ApplyUserContentHeaders(response);
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
        }).RequireRateLimiting("DownloadEndpoints");

        app.MapGet("/s/{token}/files/{fileId:guid}/preview", async (
            ShareManager manager,
            SharePreviewJobService previewJobService,
            string token,
            Guid fileId,
            HttpRequest request,
            CancellationToken ct) =>
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
            if (share is null)
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
            if (share is null)
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
            if (availability.State == "pending")
            {
                previewJobService.QueueGeneration(share.Id, file.Id);
            }

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
            if (share is null)
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
        }).RequireRateLimiting("DownloadEndpoints");

        app.MapGet("/s/{token}/gallery", (string token) => Results.Redirect($"/s/{token}"));

        app.MapGet("/s/{token}/download", (string token) =>
        {
            return Results.Redirect($"/s/{token}");
        }).RequireRateLimiting("DownloadEndpoints");

        app.MapPost("/s/{token}/download", async (ShareManager manager, IObjectStore objectStore, IOptions<AgoraOptions> options, string token, HttpRequest request, CancellationToken ct) =>
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

            var archive = ObjectKey.TryNormalize(share.ZipDiskPath, out var archiveKey)
                ? await objectStore.OpenReadAsync(archiveKey, ct)
                : null;
            if (archive is null)
            {
                return Results.StatusCode(StatusCodes.Status410Gone);
            }

            var isAuthenticatedRequester = request.HttpContext.User.Identity?.IsAuthenticated == true;
            Task RecordDownloadAsync() => isAuthenticatedRequester
                ? Task.CompletedTask
                : manager.RecordDownloadAsync(share, token, ResolveRequesterIp(request), request.Headers.UserAgent.ToString(), ct);

            if (string.IsNullOrWhiteSpace(share.DownloadPasswordHash))
            {
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

            await using (archive.Content)
            {
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

                return await EncryptedArchiveDownload.ServeAsync(
                        request.HttpContext,
                        archive.Content,
                        downloadPassword,
                        options.Value.StorageRoot,
                        share.ZipDisplayName,
                        RecordDownloadAsync,
                        ct)
                    ?? Results.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=invalid_password");
            }
        }).RequireRateLimiting("DownloadEndpoints");

        return app;
    }

    private static string ResolveRequesterIp(HttpRequest request)
    {
        var remoteRaw = request.HttpContext.Connection.RemoteIpAddress?.ToString();
        if (IpAddressUtilities.TryNormalizeIp(remoteRaw, out var remoteIp) && IpAddressUtilities.IsPublicRoutable(remoteIp))
        {
            return remoteIp;
        }

        var directHeaderCandidates = new[]
        {
            request.Headers["CF-Connecting-IP"].ToString(),
            request.Headers["True-Client-IP"].ToString(),
            request.Headers["X-Real-IP"].ToString()
        };

        foreach (var candidate in directHeaderCandidates)
        {
            if (!IpAddressUtilities.TryNormalizeIp(candidate, out var normalized))
            {
                continue;
            }

            if (IpAddressUtilities.IsPublicRoutable(normalized))
            {
                return normalized;
            }
        }

        var forwardedForHeader = request.Headers["X-Forwarded-For"].ToString();
        var fromForwardedFor = IpAddressUtilities.ExtractFromForwardedFor(forwardedForHeader, preferPublic: true);
        if (!string.IsNullOrWhiteSpace(fromForwardedFor))
        {
            return fromForwardedFor;
        }

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            return remoteIp;
        }

        var fallbackForwarded = IpAddressUtilities.ExtractFromForwardedFor(forwardedForHeader, preferPublic: false);
        if (!string.IsNullOrWhiteSpace(fallbackForwarded))
        {
            return fallbackForwarded;
        }

        return "unknown";
    }
}
