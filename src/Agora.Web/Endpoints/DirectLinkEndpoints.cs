using Agora.Application.Abstractions;
using Agora.Application.Models;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Microsoft.AspNetCore.Mvc;

namespace Agora.Web.Endpoints;

/// <summary>
/// Creates a temporary direct link from the single file staged into a draft. Everything refusable (draft state,
/// file count and type, duration, scratch) is checked before the draft is sealed, so a refusal never costs the
/// sender the draft; only infrastructure failures reach the seal/unseal path (503).
/// </summary>
public static class DirectLinkEndpoints
{
    public const string LoggerCategory = "Agora.DirectLinks";

    public sealed record CreateDirectLinkRequest(string? DraftShareId, string? UploadId, string? Duration);

    public static IEndpointRouteBuilder MapDirectLinkEndpoints(this IEndpointRouteBuilder app)
    {
        // Authenticated callers are covered by the global per-user rate limit partition.
        app.MapPost("/api/shares/direct-link", CreateAsync)
            .RequireAuthorization()
            .WithMetadata(new UploadEndpointMetadata(RequiresHeaderCsrfToken: true), new RequestSizeLimitAttribute(16 * 1024));

        return app;
    }

    private static async Task<IResult> CreateAsync(
        HttpContext context,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        IPublicOriginProvider publicOrigin,
        ILoggerFactory loggerFactory,
        CreateDirectLinkRequest body,
        CancellationToken ct)
    {
        if (!context.User.TryGetShareOwner(out var owner))
        {
            return Results.Unauthorized();
        }

        var draftShareId = (body.DraftShareId ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(draftShareId))
        {
            return Results.BadRequest(new { error = "draftShareId is required." });
        }

        if (!DirectLinkDurations.TryParse(body.Duration, out var duration))
        {
            return Results.BadRequest(new { error = "duration must be 30m, 6h, 1d or 7d." });
        }

        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadStagingEndpoints.UploadLimitJson(ex);
        }

        var logger = loggerFactory.CreateLogger(LoggerCategory);
        return (await CreateFromDraftAsync(manager, scratchSpace, publicOrigin, logger, owner, draftShareId, body.UploadId ?? string.Empty, duration, ct)).Response;
    }

    /// <summary>The outcome of <see cref="CreateFromDraftAsync"/>; <see cref="Created"/> is false for every refusal.</summary>
    public sealed record CreateOutcome(IResult Response, bool Created);

    /// <summary>
    /// The result of <see cref="CreateCoreAsync"/>: <see cref="Share"/> on success, else the HTTP status and message of
    /// the refusal.
    /// </summary>
    public sealed record CoreOutcome(CreateShareResult? Share, int Status, string? Error);

    /// <summary>
    /// Turns the single staged file of an open draft into a direct link and answers with the browser/capture JSON.
    /// </summary>
    public static async Task<CreateOutcome> CreateFromDraftAsync(
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        IPublicOriginProvider publicOrigin,
        ILogger logger,
        ShareOwner owner,
        string draftShareId,
        string uploadId,
        DirectLinkDuration duration,
        CancellationToken ct)
    {
        var outcome = await CreateCoreAsync(manager, scratchSpace, logger, owner, draftShareId, uploadId, duration, null, ct);
        if (outcome.Share is not { } created)
        {
            return new CreateOutcome(Results.Json(new { error = outcome.Error }, statusCode: outcome.Status), false);
        }

        return new CreateOutcome(Results.Ok(new
        {
            url = publicOrigin.ShareUrl(created.Token),
            token = created.Token,
            expiresAtUtc = created.ExpiresAtUtc
        }), true);
    }

    /// <summary>
    /// Turns the single staged file of an open draft into a direct link: resolve and admit (refusals leave the draft
    /// unsealed), seal and create inline (a failure unseals it again: 503), then remove the draft scratch. Shared by
    /// the browser flow, the capture API and the agent API so all keep identical seal and compensation behavior.
    /// </summary>
    public static async Task<CoreOutcome> CreateCoreAsync(
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        ILogger logger,
        ShareOwner owner,
        string draftShareId,
        string uploadId,
        DirectLinkDuration duration,
        Guid? createdByApiTokenId,
        CancellationToken ct)
    {
        ShareManager.StagedUploadFile staged;
        try
        {
            staged = await manager.ResolveDirectLinkUploadAsync(owner.UserId, draftShareId, uploadId, ct);
            scratchSpace.EnsureCanAdmit(scratchSpace.DurableDemand(staged.OriginalSizeBytes));
        }
        catch (InvalidOperationException ex)
        {
            return new CoreOutcome(null, StatusCodes.Status400BadRequest, ex.Message);
        }
        catch (UploadLimitException ex)
        {
            return new CoreOutcome(null, ex.StatusCode, ex.Message);
        }

        var command = new CreateDirectLinkCommand(owner.UserId, owner.Email, staged.UploadId, draftShareId, duration, createdByApiTokenId);
        CreateShareResult? created = null;
        try
        {
            // Sealing makes a second submission of the draft a 409; the share is created inline (no queue), and a
            // failure unseals the draft again and reports a retryable 503.
            if (!await manager.SealDraftForSubmissionAsync(owner.UserId, draftShareId, async () => { created = await manager.CreateDirectLinkShareAsync(command, ct); }, ct))
            {
                return new CoreOutcome(null, StatusCodes.Status409Conflict, "This upload was already submitted.");
            }
        }
        catch (UploadLimitException ex)
        {
            return new CoreOutcome(null, ex.StatusCode, ex.Message);
        }

        if (created is null)
        {
            return new CoreOutcome(null, StatusCodes.Status503ServiceUnavailable, "The direct link could not be created right now.");
        }

        try
        {
            await manager.FinalizeDraftAsync(owner.UserId, draftShareId, ct);
        }
        catch (Exception ex)
        {
            // The share is committed; leftovers in scratch are removed by the zombie sweep.
            logger.LogWarning(ex, "Unable to remove draft scratch after creating a direct link; the zombie sweep will");
        }

        return new CoreOutcome(created, StatusCodes.Status201Created, null);
    }
}
