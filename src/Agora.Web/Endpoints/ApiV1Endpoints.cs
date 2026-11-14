using System.Text.Json;
using System.Text.Json.Serialization;
using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Agents;
using Agora.Web.Auth;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Agora.Web.Endpoints;

/// <summary>
/// The API of connected apps (contract: <c>docs/api/v1.md</c>). Every endpoint requires an API bearer token
/// (<see cref="ApiTokenDefaults.ApiClientPolicy"/>); the anonymous code exchange lives in <see cref="OAuthEndpoints"/>.
/// Cookies are never accepted here and CSRF does not apply (<see cref="ApiEndpointMetadata"/>).
/// Authenticated callers share the global per-user rate limit partition.
/// </summary>
public static class ApiV1Endpoints
{
    public static IEndpointRouteBuilder MapApiV1Endpoints(this IEndpointRouteBuilder app, long captureRequestBodyLimit)
    {
        var api = app.MapGroup("/api/v1")
            .WithMetadata(ApiEndpointMetadata.Instance)
            .RequireAuthorization(ApiTokenDefaults.ApiClientPolicy)
            .DisableAntiforgery();

        api.MapDelete("/auth/token", RevokeTokenAsync);
        api.MapGet("/me", Me);
        api.MapPost("/captures", CreateCaptureAsync)
            .RequireAuthorization(ApiTokenDefaults.CapturePolicy)
            .WithMetadata(new RequestSizeLimitAttribute(captureRequestBodyLimit));
        api.MapDelete("/shares/{token}", DeleteShareAsync);

        return app;
    }

    private static async Task<IResult> RevokeTokenAsync(HttpContext context, ApiTokenService tokens, CancellationToken ct)
    {
        if (ApiTokenDefaults.TokenId(context.User) is not { } tokenId || context.User.UserId() is not { } userId)
        {
            return ApiError(StatusCodes.Status401Unauthorized, "An API token is required.");
        }

        await tokens.RevokeAsync(tokenId, userId, ct);
        return Results.NoContent();
    }

    private static IResult Me(HttpContext context, IOptions<AgoraOptions> options)
    {
        if (!context.User.TryGetShareOwner(out var owner))
        {
            return ApiError(StatusCodes.Status401Unauthorized, "An API token is required.");
        }

        var cfg = options.Value;
        return Results.Ok(new
        {
            email = owner.Email,
            displayName = context.User.Identity?.Name ?? owner.Email,
            serverVersion = AppVersion.Current,
            accessLevel = ApiTokenDefaults.AccessLevel(context.User),
            limits = AgentLimits.Describe(cfg),
            // One capture is one file in one draft: both the per-file and the per-share limit apply.
            maxFileSizeBytes = MaxCaptureBytes(cfg),
            directLinkDurations = DirectLinkDurations.All.Select(DirectLinkDurations.ToWireValue).ToArray()
        });
    }

    /// <summary>
    /// Stages the <c>file</c> part into a fresh draft and turns it into a direct link in one call. Duration, identity
    /// and the scratch reservation for the multipart buffer are settled from the query string before the body is
    /// read; the draft is deleted on every refusal, so nothing is left behind for the zombie sweep.
    /// </summary>
    private static async Task<IResult> CreateCaptureAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        UploadConcurrency concurrency,
        IPublicOriginProvider publicOrigin,
        IOptions<AgoraOptions> options,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        if (!context.User.TryGetShareOwner(out var owner))
        {
            return ApiError(StatusCodes.Status401Unauthorized, "An API token is required.");
        }

        if (!DirectLinkDurations.TryParse(context.Request.Query["duration"].ToString(), out var duration))
        {
            return ApiError(StatusCodes.Status400BadRequest,
                $"duration must be one of {string.Join(", ", DirectLinkDurations.All.Select(DirectLinkDurations.ToWireValue))}.");
        }

        if (!context.Request.HasFormContentType)
        {
            return ApiError(StatusCodes.Status400BadRequest, "Expected multipart/form-data with one part named file.");
        }

        // Each capture opens its own draft, so the in-flight cap is per account.
        if (!concurrency.TryAdmit(context, UploadConcurrency.AccountKey(owner.UserId)))
        {
            return ApiError(StatusCodes.Status429TooManyRequests, UploadConcurrency.RefusalMessage);
        }

        var cfg = options.Value;
        string draftShareId;
        long bodyCap;
        try
        {
            // Scratch first, so a 507 leaves no draft behind.
            bodyCap = UploadStagingEndpoints.ReserveRequestBuffer(context, scratchSpace, MaxCaptureBytes(cfg));
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, Guid.NewGuid().ToString("N"), ct);
        }
        catch (InvalidOperationException ex)
        {
            return ApiError(StatusCodes.Status400BadRequest, ex.Message);
        }
        catch (UploadLimitException ex)
        {
            return UploadStagingEndpoints.UploadLimitJson(ex);
        }

        var logger = loggerFactory.CreateLogger(DirectLinkEndpoints.LoggerCategory);
        var created = false;
        try
        {
            var stage = await StageCaptureAsync(context.Request, manager, cfg, owner.UserId, draftShareId, bodyCap, ct);
            if (stage.Refusal is not null)
            {
                return stage.Refusal;
            }

            var outcome = await DirectLinkEndpoints.CreateFromDraftAsync(
                manager,
                scratchSpace,
                publicOrigin,
                logger,
                owner,
                draftShareId,
                stage.Staged!.UploadId,
                duration,
                ct);
            created = outcome.Created;
            return outcome.Response;
        }
        finally
        {
            if (!created)
            {
                await DiscardDraftAsync(manager, logger, owner.UserId, draftShareId);
            }
        }
    }

    /// <summary>Removes the staged payload and the draft; CancellationToken.None so an aborted request still cleans up.</summary>
    private static async Task DiscardDraftAsync(ShareManager manager, ILogger logger, Guid ownerUserId, string draftShareId)
    {
        try
        {
            await manager.FinalizeDraftAsync(ownerUserId, draftShareId, CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to remove the draft of a refused capture; the zombie sweep will");
        }
    }

    /// <summary>Reads the <c>file</c> part, accepts only a PNG or JPEG (extension and signature agree) and stages it.</summary>
    private static async Task<UploadStagingEndpoints.StageResult> StageCaptureAsync(
        HttpRequest request,
        ShareManager manager,
        AgoraOptions cfg,
        Guid ownerUserId,
        string draftShareId,
        long bodyCap,
        CancellationToken ct)
    {
        // Parsed up to the admitted body cap; an oversized or malformed body is the same 413/400 as on the stage routes.
        var read = await UploadStagingEndpoints.ReadUploadFormAsync(request, bodyCap, ct);
        if (read.Refusal is not null)
        {
            return new UploadStagingEndpoints.StageResult(null, read.Refusal);
        }

        var file = read.Form!.Files["file"] is { Length: > 0 } part ? part : null;
        if (file is null)
        {
            return Refuse(StatusCodes.Status400BadRequest, "A file part named file is required.");
        }

        // A capture is one file in one draft, so both the per-file and the per-share limit apply (as /me reports).
        if (file.Length > MaxCaptureBytes(cfg))
        {
            return Refuse(StatusCodes.Status413PayloadTooLarge, UploadStagingEndpoints.TooLargeMessage);
        }

        if (!await CaptureImages.IsPngOrJpegAsync(file, ct))
        {
            return Refuse(StatusCodes.Status400BadRequest, "Only PNG or JPEG images are accepted.");
        }

        return await UploadStagingEndpoints.StageFileAsync(file, manager, cfg, ownerUserId, draftShareId, ShareManager.UploadPurposeShareFile, ct);

        static UploadStagingEndpoints.StageResult Refuse(int statusCode, string error) => new(null, ApiError(statusCode, error));
    }

    /// <summary>
    /// Deletes one of the caller's own direct links early (capture tokens; agent tokens delete by access level), through the same path as the web UI. Not found, someone
    /// else's and not a direct link all answer the same 404; an already deleted link answers 204 again (and its file
    /// cleanup is queued again).
    /// </summary>
    private static async Task<IResult> DeleteShareAsync(string token, HttpContext context, ShareManager manager, CancellationToken ct)
    {
        if (!context.User.TryGetShareOwner(out var owner))
        {
            return ApiError(StatusCodes.Status401Unauthorized, "An API token is required.");
        }

        // Agent tokens delete by access level (own: the shares the token created; all: any share of the account).
        if (AgentCaller.FromPrincipal(context.User) is { } agent)
        {
            return (await context.RequestServices.GetRequiredService<AgentShareService>().DeleteShareAsync(agent, token, ct)).ToHttp(_ => Results.NoContent());
        }

        var share = ShareTokens.IsValid(token) ? await manager.FindByTokenForUploaderAsync(token, owner, ct) : null;
        // Exact match: SQL Server's default collation would also match a token that differs only in case.
        if (share is null || !string.Equals(share.ShareToken, token, StringComparison.Ordinal) || !ShareModes.IsDirectLink(share.AccessMode))
        {
            return ApiError(StatusCodes.Status404NotFound, "No such direct link.");
        }

        // Always through the manager, even when the row is already marked deleted: it is idempotent and, with requeueCleanup, queues the
        // file cleanup, so a retry after a failed enqueue still removes the durable content.
        await manager.DeleteShareAsync(share.Id, owner, ct, requeueCleanup: true);
        return Results.NoContent();
    }

    private static long MaxCaptureBytes(AgoraOptions cfg) => Math.Min(cfg.MaxFileSizeBytes, cfg.MaxTotalUploadBytes);

    private static IResult ApiError(int statusCode, string error) => Results.Json(new { error }, statusCode: statusCode);
}

/// <summary>Signature check for captures: the extension and the first bytes must both say PNG, or both say JPEG.</summary>
public static class CaptureImages
{
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] JpegSignature = [0xFF, 0xD8, 0xFF];

    public static async Task<bool> IsPngOrJpegAsync(IFormFile file, CancellationToken ct)
    {
        var header = new byte[PngSignature.Length];
        await using var stream = file.OpenReadStream();
        var read = await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, ct);
        return Matches(file.FileName, header.AsSpan(0, read));
    }

    public static bool Matches(string? fileName, ReadOnlySpan<byte> header)
    {
        var extension = Path.GetExtension(fileName ?? string.Empty).ToLowerInvariant();
        return extension switch
        {
            ".png" => header.StartsWith(PngSignature),
            ".jpg" or ".jpeg" => header.StartsWith(JpegSignature),
            _ => false
        };
    }
}
