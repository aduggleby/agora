using Microsoft.AspNetCore.Http.Features;
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
using Agora.Web.Services;

namespace Agora.Web.Endpoints;

/// <summary>
/// The three endpoints that write a file into staging. Each one resolves identity and the draft from the query string,
/// runs admission (draft caps, sealed check, in-flight caps per client and per draft, scratch budget) and reserves
/// scratch for the multipart buffer before the body is read; the staging copy then takes its own reservation. Bodies
/// are capped at what the draft still accepts plus overhead and the CSRF token must come in the header
/// (<see cref="UploadEndpointMetadata"/>).
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
    // A per-address key, not the address itself: IPv6 clients are grouped by /64 (ClientAddresses).
    public static string ClientAddress(HttpContext context) =>
        ClientAddresses.PartitionKey(context.Connection.RemoteIpAddress);

    /// <summary>The one 413 text of every upload route (stage, template, capture), whichever check refuses.</summary>
    public const string TooLargeMessage = "The file is larger than this upload accepts.";

    /// <summary>Room for multipart framing and form fields on top of the file itself.</summary>
    public const long MultipartOverheadBytes = 1024 * 1024;

    /// <summary>
    /// The most this request's body may carry: the file allowance plus multipart overhead, never more than the
    /// endpoint's own RequestSizeLimit.
    /// </summary>
    private static long RequestBodyCap(HttpContext context, long allowanceBytes)
    {
        var cap = Math.Max(0, allowanceBytes) + MultipartOverheadBytes;
        var endpointLimit = context.GetEndpoint()?.Metadata.GetMetadata<IRequestSizeLimitMetadata>()?.MaxRequestBodySize;
        return endpointLimit is { } limit ? Math.Min(limit, cap) : cap;
    }

    /// <summary>Scratch the multipart buffer can take, known before the body is read: min(Content-Length, cap).</summary>
    private static ScratchDemand RequestBufferDemand(HttpContext context, long allowanceBytes)
    {
        var cap = RequestBodyCap(context, allowanceBytes);
        return ScratchDemand.Scratch(Math.Min(context.Request.ContentLength ?? cap, cap));
    }

    private static async Task<IResult> StageShareFileAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        UploadConcurrency concurrency,
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
        long bodyCap;
        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
            if (!concurrency.TryAdmit(context, UploadConcurrency.AccountKey(owner.UserId), UploadConcurrency.DraftKey(draftShareId)))
            {
                return UploadConcurrency.TooManyJson();
            }

            bodyCap = ReserveRequestBuffer(context, scratchSpace, ShareFileAllowance(manager, cfg, draftShareId));
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        return await StageFormFileAsync(request, manager, cfg, owner.UserId, draftShareId, ShareManager.UploadPurposeShareFile, "A file is required.", bodyCap, ct);
    }

    private static async Task<IResult> StageTemplateBackgroundAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        UploadConcurrency concurrency,
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
        long bodyCap;
        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
            if (!concurrency.TryAdmit(context, UploadConcurrency.AccountKey(owner.UserId), UploadConcurrency.DraftKey(draftShareId)))
            {
                return UploadConcurrency.TooManyJson();
            }

            // A background is not counted against the share's file total, only against the per-file limit.
            bodyCap = ReserveRequestBuffer(context, scratchSpace, cfg.MaxFileSizeBytes);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        var read = await ReadUploadFormAsync(request, bodyCap, ct);
        if (read.Refusal is not null)
        {
            return read.Refusal;
        }

        var file = read.Form!.Files["file"];
        if (file is null || file.Length <= 0)
        {
            return Results.BadRequest(new { error = "An image file is required." });
        }

        if (!ContentTypePolicy.IsAllowedBackgroundImage(file.FileName))
        {
            return Results.BadRequest(new { error = "Only JPG, PNG, or WEBP files are allowed." });
        }

        // Header only (format and pixel budget), so the share page's link-preview render never meets an oversized image.
        await using (var header = file.OpenReadStream())
        {
            if (!OgImageGenerator.IsAcceptableBackground(header))
            {
                return Results.BadRequest(new { error = OgImageGenerator.BackgroundRefusalMessage });
            }
        }

        return (await StageFileAsync(file, manager, cfg, owner.UserId, draftShareId, ShareManager.UploadPurposeTemplateBackground, ct)).ToResponse();
    }

    private static async Task<IResult> StagePublicUploadAsync(
        AuthService authService,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        UploadConcurrency concurrency,
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

        if (!concurrency.TryAdmit(context, UploadConcurrency.AddressKey(ClientAddress(context))))
        {
            return UploadConcurrency.TooManyJson();
        }

        var cfg = options.Value;
        long bodyCap;
        try
        {
            // Scratch is checked first, so a 507 normally leaves no empty draft behind; a new draft then counts
            // against the open-draft caps of this upload code and of the client address. The reservation itself is
            // sized from the draft's remaining allowance, which is only read once the draft is known to be ours.
            scratchSpace.EnsureCanAdmit(RequestBufferDemand(context, cfg.MaxFileSizeBytes));
            draftShareId = await manager.EnsurePublicUploadDraftAsync(user.Id, draftShareId, user.UploadToken, ClientAddress(context), ct);
            if (!concurrency.TryAdmit(context, UploadConcurrency.DraftKey(draftShareId)))
            {
                return UploadConcurrency.TooManyJson();
            }

            bodyCap = ReserveRequestBuffer(context, scratchSpace, ShareFileAllowance(manager, cfg, draftShareId));
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadLimitJson(ex);
        }

        return await StageFormFileAsync(request, manager, cfg, user.Id, draftShareId, ShareManager.UploadPurposeShareFile, "A file is required.", bodyCap, ct);
    }

    /// <summary>
    /// What one more share file may still add to a draft: the per-file limit, or less when the draft is close to the
    /// per-share total. Throws 413 when nothing is left.
    /// </summary>
    private static long ShareFileAllowance(ShareManager manager, AgoraOptions cfg, string draftShareId)
    {
        var remaining = manager.GetDraftRemainingShareBytes(draftShareId);
        if (remaining <= 0)
        {
            throw new UploadLimitException(UploadLimitKind.TooManyBytes, "Total upload size exceeds the limit per share.");
        }

        return Math.Min(cfg.MaxFileSizeBytes, remaining);
    }

    /// <summary>
    /// Holds scratch for the multipart buffer ASP.NET writes under tmp/aspnet until the request (and with it the
    /// buffered form) is disposed, sized min(Content-Length, allowance + overhead) rather than the endpoint maximum,
    /// and caps the request body at that size so the buffer can never outgrow its reservation. Also raises the
    /// minimum body data rate so a stalled upload releases its reservation. Throws 413 (declared body too large)
    /// or 507; returns the body cap to parse the form with.
    /// </summary>
    public static long ReserveRequestBuffer(HttpContext context, ScratchSpaceMonitor scratchSpace, long allowanceBytes)
    {
        var cap = RequestBodyCap(context, allowanceBytes);
        if (context.Request.ContentLength is { } declared && declared > cap)
        {
            throw new UploadLimitException(UploadLimitKind.TooManyBytes, TooLargeMessage);
        }

        var reservation = scratchSpace.Reserve(RequestBufferDemand(context, allowanceBytes));
        context.Response.RegisterForDispose(reservation);
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySize)
        {
            bodySize.MaxRequestBodySize = cap;
        }

        UploadConcurrency.ApplyMinBodyDataRate(context);
        return cap;
    }

    /// <summary>The parsed form, or the refusal for a body that is too large (413) or malformed (400).</summary>
    public sealed record FormReadResult(IFormCollection? Form, IResult? Refusal);

    /// <summary>
    /// Parses a multipart upload with a per-call limit (the app-wide form limits are deliberately small, so only the
    /// upload endpoints can buffer a file, and never past <paramref name="bodyCap"/>).
    /// </summary>
    public static async Task<FormReadResult> ReadUploadFormAsync(HttpRequest request, long bodyCap, CancellationToken ct)
    {
        try
        {
            var form = await request.ReadFormAsync(UploadFormOptions(bodyCap), ct);
            return new FormReadResult(form, null);
        }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            return new FormReadResult(null, Results.Json(new { error = TooLargeMessage }, statusCode: StatusCodes.Status413PayloadTooLarge));
        }
        catch (InvalidDataException ex) when (ex.Message.Contains("length limit", StringComparison.OrdinalIgnoreCase))
        {
            return new FormReadResult(null, Results.Json(new { error = TooLargeMessage }, statusCode: StatusCodes.Status413PayloadTooLarge));
        }
        catch (Exception ex) when (ex is BadHttpRequestException or InvalidDataException)
        {
            return new FormReadResult(null, Results.BadRequest(new { error = "The multipart body could not be read." }));
        }
    }

    /// <summary>Form limits for an upload request: the file part up to the body cap, everything else as small as app-wide.</summary>
    public static FormOptions UploadFormOptions(long bodyCap) => new()
    {
        MultipartBodyLengthLimit = bodyCap,
        ValueLengthLimit = FormLimits.ValueLengthLimit,
        ValueCountLimit = FormLimits.ValueCountLimit
    };

    private static async Task<IResult> StageFormFileAsync(
        HttpRequest request,
        ShareManager manager,
        AgoraOptions cfg,
        Guid ownerUserId,
        string draftShareId,
        string purpose,
        string missingFileError,
        long bodyCap,
        CancellationToken ct)
    {
        var read = await ReadUploadFormAsync(request, bodyCap, ct);
        if (read.Refusal is not null)
        {
            return read.Refusal;
        }

        var file = read.Form!.Files["file"];
        if (file is null || file.Length <= 0)
        {
            return Results.BadRequest(new { error = missingFileError });
        }

        return (await StageFileAsync(file, manager, cfg, ownerUserId, draftShareId, purpose, ct)).ToResponse();
    }

    /// <summary>A staged file, or the refusal to answer with (400, or the <see cref="UploadLimitException"/> status).</summary>
    public sealed record StageResult(ShareManager.StagedUploadFile? Staged, IResult? Refusal)
    {
        public IResult ToResponse() => Refusal ?? Results.Ok(new
        {
            uploadId = Staged!.UploadId,
            fileName = Staged.OriginalFileName,
            sizeBytes = Staged.OriginalSizeBytes,
            // Whether a temporary direct link may serve this file inline; the browser never duplicates the allowlist.
            directLinkEligible = ContentTypePolicy.Resolve(Staged.OriginalFileName).Inline
        });
    }

    /// <summary>
    /// Stages one buffered file into the draft: the shared core of every staging endpoint and of the capture API, so
    /// size checks and refusal mapping are identical everywhere.
    /// </summary>
    public static async Task<StageResult> StageFileAsync(
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
            return new StageResult(null, Results.BadRequest(new { error = $"File '{file.FileName}' exceeds max size." }));
        }

        await using var stream = file.OpenReadStream();
        try
        {
            var staged = await manager.StageUploadAsync(ownerUserId, draftShareId, file.FileName, file.Length, stream, ct, purpose);
            return new StageResult(staged, null);
        }
        catch (InvalidOperationException ex)
        {
            return new StageResult(null, Results.BadRequest(new { error = ex.Message }));
        }
        catch (UploadLimitException ex)
        {
            return new StageResult(null, UploadLimitJson(ex));
        }
    }
}
