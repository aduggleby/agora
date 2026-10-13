using Microsoft.AspNetCore.Http.Metadata;
using System.Security.Claims;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using Agora.Web.Auth;

namespace Agora.Web.Endpoints;

/// <summary>
/// The three endpoints that write a file into staging. Each one resolves identity and the draft from the query string,
/// runs admission (draft caps, sealed check, scratch budget) and reserves scratch for the multipart buffer before the
/// body is read; the staging copy then takes its own reservation. Bodies are capped at one file plus overhead and the
/// CSRF token must come in the header (<see cref="UploadEndpointMetadata"/>).
/// </summary>
public static class UploadStagingEndpoints
{
    public static IEndpointRouteBuilder MapUploadStagingEndpoints(this IEndpointRouteBuilder app, long stageRequestBodyLimit)
    {
        app.MapPost("/api/uploads/stage", StageShareFileAsync)
            .RequireAuthorization()
            .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: true), new RequestSizeLimitAttribute(stageRequestBodyLimit));

        app.MapPost("/api/uploads/stage-template-background", StageTemplateBackgroundAsync)
            .RequireAuthorization()
            .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: true), new RequestSizeLimitAttribute(stageRequestBodyLimit));

        app.MapPost("/api/public-uploads/stage", StagePublicUploadAsync)
            .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints)
            .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: true), new RequestSizeLimitAttribute(stageRequestBodyLimit));

        return app;
    }

    // Quota refusals: 400 (file count), 413 (bytes), 409 (draft sealed or gone), 429 (open drafts, daily quota),
    // 503 (queue unavailable) or 507 (scratch full).
    public static IResult UploadLimitJson(UploadLimitException ex) =>
        Results.Json(new { error = ex.Message }, statusCode: ex.StatusCode);

    public static IResult UploadLimitText(UploadLimitException ex) =>
        Results.Text(ex.Message, statusCode: ex.StatusCode);

    // Forwarded headers from trusted proxies have already replaced RemoteIpAddress by the time endpoints run.
    public static string ClientAddress(HttpContext context) =>
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    /// <summary>
    /// Scratch the multipart buffer of a request can take, known before its body is read: min(Content-Length, limit),
    /// or the full limit for a chunked body. The limit is the endpoint's own RequestSizeLimit (the most Kestrel lets
    /// through), falling back to the configured maximum when an endpoint carries none.
    /// </summary>
    private static ScratchDemand RequestBufferDemand(HttpContext context, long fallbackMaxBodyBytes)
    {
        var limit = context.GetEndpoint()?.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize ?? fallbackMaxBodyBytes;
        return ScratchDemand.Scratch(Math.Min(context.Request.ContentLength ?? limit, limit));
    }

    private static async Task<IResult> StageShareFileAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        IOptions<AgoraOptions> options,
        HttpRequest request,
        CancellationToken ct)
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected multipart/form-data." });
        }

        if (!context.User.TryGetShareOwner(out var owner))
        {
            return Results.Unauthorized();
        }

        // Identity and admission come from the query string so they run before the multipart body is buffered.
        var draftShareId = request.Query["draftShareId"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(draftShareId))
        {
            return Results.BadRequest(new { error = "draftShareId query parameter is required." });
        }

        var cfg = options.Value;
        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
            ReserveRequestBuffer(context, scratchSpace, cfg.MaxFileSizeBytes);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        return await StageFormFileAsync(request, manager, cfg, owner.UserId, draftShareId, ShareManager.UploadPurposeShareFile, "A file is required.", ct);
    }

    private static async Task<IResult> StageTemplateBackgroundAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        IOptions<AgoraOptions> options,
        HttpRequest request,
        CancellationToken ct)
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected multipart/form-data." });
        }

        if (!context.User.TryGetShareOwner(out var owner))
        {
            return Results.Unauthorized();
        }

        var draftShareId = request.Query["draftShareId"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(draftShareId))
        {
            return Results.BadRequest(new { error = "draftShareId query parameter is required." });
        }

        var cfg = options.Value;
        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
            ReserveRequestBuffer(context, scratchSpace, cfg.MaxFileSizeBytes);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        var form = await request.ReadFormAsync(ct);
        var file = form.Files["file"];
        if (file is null || file.Length <= 0)
        {
            return Results.BadRequest(new { error = "An image file is required." });
        }

        if (!ContentTypePolicy.IsAllowedBackgroundImage(file.FileName))
        {
            return Results.BadRequest(new { error = "Only JPG, PNG, or WEBP files are allowed." });
        }

        return await StageFileAsync(file, manager, cfg, owner.UserId, draftShareId, ShareManager.UploadPurposeTemplateBackground, ct);
    }

    private static async Task<IResult> StagePublicUploadAsync(
        AuthService authService,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        IOptions<AgoraOptions> options,
        HttpContext context,
        HttpRequest request,
        CancellationToken ct)
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Expected multipart/form-data." });
        }

        var uploadToken = request.Query["uploadToken"].ToString().Trim();
        var draftShareId = request.Query["draftShareId"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(uploadToken) || string.IsNullOrWhiteSpace(draftShareId))
        {
            return Results.BadRequest(new { error = "uploadToken and draftShareId query parameters are required." });
        }

        var user = await authService.FindByUploadTokenAsync(uploadToken, ct);
        if (user is null)
        {
            return Results.NotFound(new { error = "Upload link not found." });
        }

        var cfg = options.Value;
        try
        {
            // Scratch first, so a 507 leaves no empty draft behind; a new draft then counts against the open-draft
            // caps of this upload code and of the client address.
            ReserveRequestBuffer(context, scratchSpace, cfg.MaxFileSizeBytes);
            draftShareId = await manager.EnsurePublicUploadDraftAsync(user.Id, draftShareId, user.UploadToken, ClientAddress(context), ct);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        return await StageFormFileAsync(request, manager, cfg, user.Id, draftShareId, ShareManager.UploadPurposeShareFile, "A file is required.", ct);
    }

    /// <summary>
    /// Holds scratch for the multipart buffer ASP.NET writes under tmp/aspnet until the request (and with it the
    /// buffered form) is disposed. Two uploads that each fit cannot both buffer past the budget. Throws 507.
    /// </summary>
    public static void ReserveRequestBuffer(HttpContext context, ScratchSpaceMonitor scratchSpace, long maxBodyBytes)
    {
        var reservation = scratchSpace.Reserve(RequestBufferDemand(context, maxBodyBytes));
        context.Response.RegisterForDispose(reservation);
    }

    private static async Task<IResult> StageFormFileAsync(
        HttpRequest request,
        ShareManager manager,
        AgoraOptions cfg,
        Guid ownerUserId,
        string draftShareId,
        string purpose,
        string missingFileError,
        CancellationToken ct)
    {
        var form = await request.ReadFormAsync(ct);
        var file = form.Files["file"];
        if (file is null || file.Length <= 0)
        {
            return Results.BadRequest(new { error = missingFileError });
        }

        return await StageFileAsync(file, manager, cfg, ownerUserId, draftShareId, purpose, ct);
    }

    private static async Task<IResult> StageFileAsync(
        IFormFile file,
        ShareManager manager,
        AgoraOptions cfg,
        Guid ownerUserId,
        string draftShareId,
        string purpose,
        CancellationToken ct)
    {
        if (file.Length > cfg.MaxFileSizeBytes)
        {
            return Results.BadRequest(new { error = $"File '{file.FileName}' exceeds max size." });
        }

        await using var stream = file.OpenReadStream();
        ShareManager.StagedUploadFile staged;
        try
        {
            staged = await manager.StageUploadAsync(ownerUserId, draftShareId, file.FileName, file.Length, stream, ct, purpose);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        return Results.Ok(new
        {
            uploadId = staged.UploadId,
            fileName = staged.OriginalFileName,
            sizeBytes = staged.OriginalSizeBytes
        });
    }
}
