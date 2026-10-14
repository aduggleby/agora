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

        ShareManager.StagedUploadFile staged;
        try
        {
            draftShareId = await manager.EnsureDraftShareAsync(owner.UserId, draftShareId, ct);
            staged = await manager.ResolveDirectLinkUploadAsync(owner.UserId, draftShareId, body.UploadId ?? string.Empty, ct);
            scratchSpace.EnsureCanAdmit(scratchSpace.DurableDemand(staged.OriginalSizeBytes));
        }
        catch (InvalidOperationException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (UploadLimitException ex)
        {
            return UploadStagingEndpoints.UploadLimitJson(ex);
        }

        var command = new CreateDirectLinkCommand(owner.UserId, owner.Email, staged.UploadId, draftShareId, duration);
        CreateShareResult? created = null;
        try
        {
            // Sealing makes a second submission of the draft a 409; the share is created inline (no queue), and a
            // failure unseals the draft again and reports a retryable 503.
            if (!await manager.SealDraftForSubmissionAsync(owner.UserId, draftShareId, async () => { created = await manager.CreateDirectLinkShareAsync(command, ct); }, ct))
            {
                return Results.Json(new { error = "This upload was already submitted." }, statusCode: StatusCodes.Status409Conflict);
            }
        }
        catch (UploadLimitException ex)
        {
            return UploadStagingEndpoints.UploadLimitJson(ex);
        }

        if (created is null)
        {
            return Results.Json(new { error = "The direct link could not be created right now." }, statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var logger = loggerFactory.CreateLogger("Agora.DirectLinks");
        try
        {
            await manager.FinalizeDraftAsync(owner.UserId, draftShareId, ct);
        }
        catch (Exception ex)
        {
            // The share is committed; leftovers in scratch are removed by the zombie sweep.
            logger.LogWarning(ex, "Unable to remove draft scratch after creating a direct link; the zombie sweep will");
        }

        return Results.Ok(new
        {
            url = publicOrigin.ShareUrl(created.Token),
            token = created.Token,
            expiresAtUtc = created.ExpiresAtUtc
        });
    }
}
