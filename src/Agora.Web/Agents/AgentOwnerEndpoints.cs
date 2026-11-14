using System.Text.Json;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Agora.Web.Agents;

/// <summary>
/// The owner's agent API under <c>/api/v1</c> (bearer tokens of level own or all) plus the two one-time URL routes
/// (<c>PUT /upload-urls/{ticket}</c> and <c>GET /download-urls/{ticket}</c>, authorized by the ticket alone).
/// Every route carries <see cref="ApiEndpointMetadata"/>; POST bodies must be JSON (415 otherwise). The inline routes
/// admit the account (two in flight) before reading the body, the one stated exception to "admit first, then parse".
/// </summary>
public static class AgentOwnerEndpoints
{
    private const long SmallBodyLimit = 64 * 1024;
    private const string InvalidTicket = "This upload URL is invalid, expired or already used.";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static IEndpointRouteBuilder MapAgentOwnerEndpoints(this IEndpointRouteBuilder app, long putRequestBodyLimit)
    {
        var agent = app.MapGroup("/api/v1")
            .WithMetadata(ApiEndpointMetadata.Instance)
            .RequireAuthorization(ApiTokenDefaults.AgentPolicy)
            .DisableAntiforgery();

        agent.MapPost("/uploads", UploadInlineAsync)
            .WithMetadata(new RequestSizeLimitAttribute(AgentLimits.InlineRequestBodyLimit));
        agent.MapPost("/upload-urls", IssueUploadUrlAsync)
            .WithMetadata(new RequestSizeLimitAttribute(SmallBodyLimit));
        agent.MapPost("/shares", CreateShareAsync)
            .WithMetadata(new RequestSizeLimitAttribute(AgentLimits.InlineRequestBodyLimit));
        agent.MapGet("/shares", ListSharesAsync);
        agent.MapGet("/shares/{token}", GetShareAsync);
        agent.MapGet("/shares/{token}/files", ListFilesAsync);
        agent.MapGet("/shares/{token}/files/{fileId}", DownloadFileAsync);

        var tickets = app.MapGroup("/api/v1")
            .WithMetadata(ApiEndpointMetadata.Instance)
            .AllowAnonymous()
            .DisableAntiforgery();
        tickets.MapPut("/upload-urls/{ticket}", PutUploadAsync)
            .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints)
            .WithMetadata(new AgentUploadRouteMetadata(TicketPut: true), new RequestSizeLimitAttribute(putRequestBodyLimit));
        tickets.MapGet("/download-urls/{ticket}", GetDownloadAsync);

        return app;
    }

    private sealed record UploadBody(string? DraftId, string? FileName, string? Text, string? ContentBase64, string? Purpose);

    private sealed record UploadUrlBody(string? DraftId, string? FileName, long SizeBytes, string? Purpose);

    private static async Task<IResult> UploadInlineAsync(HttpContext context, AgentShareService service, UploadConcurrency concurrency, CancellationToken ct)
    {
        if (Caller(context) is not { } caller)
        {
            return Unauthorized();
        }

        // Before the body is read: one account cannot hold more than two parsed bodies at once.
        if (!concurrency.TryAdmit(context, UploadConcurrency.AccountKey(caller.Owner.UserId)))
        {
            return UploadConcurrency.TooManyJson();
        }

        var (body, refusal) = await ReadJsonAsync<UploadBody>(context.Request, AgentLimits.InlineRequestBodyLimit, ct);
        if (refusal is not null)
        {
            return refusal;
        }

        var result = await service.UploadInlineAsync(caller, body!.DraftId, new InlineFile(body.FileName, body.Text, body.ContentBase64), body.Purpose, ct);
        return result.ToHttp();
    }

    private static async Task<IResult> IssueUploadUrlAsync(
        HttpContext context, AgentShareService service, PublicBaseUrlResolver origin, CancellationToken ct)
    {
        if (Caller(context) is not { } caller)
        {
            return Unauthorized();
        }

        var (body, refusal) = await ReadJsonAsync<UploadUrlBody>(context.Request, SmallBodyLimit, ct);
        if (refusal is not null)
        {
            return refusal;
        }

        var result = await service.IssueUploadUrlAsync(caller, origin.Resolve(context.Request), body!.DraftId, body.FileName, body.SizeBytes, body.Purpose, ct);
        return result.ToHttp();
    }

    private static async Task<IResult> CreateShareAsync(
        HttpContext context, AgentShareService service, PublicBaseUrlResolver origin, UploadConcurrency concurrency, CancellationToken ct)
    {
        if (Caller(context) is not { } caller)
        {
            return Unauthorized();
        }

        // Held while the body is parsed and inline files are staged; the service releases it before the readiness poll.
        var lease = concurrency.TryAcquire(UploadConcurrency.AccountKey(caller.Owner.UserId));
        if (lease is null)
        {
            return UploadConcurrency.TooManyJson();
        }

        AgentResult<AgentShareView> result;
        try
        {
            var (body, refusal) = await ReadJsonAsync<CreateShareRequest>(context.Request, AgentLimits.InlineRequestBodyLimit, ct);
            if (refusal is not null)
            {
                return refusal;
            }

            result = await service.CreateShareAsync(caller, origin.Resolve(context.Request), body!, ct, lease);
        }
        finally
        {
            lease.Dispose();
        }

        return result.ToHttp(view =>
        {
            context.Response.Headers.Location = $"/api/v1/shares/{Uri.EscapeDataString(view.Token)}";
            return Results.Json(view, statusCode: result.Status);
        });
    }

    private static async Task<IResult> ListSharesAsync(HttpContext context, AgentShareService service, PublicBaseUrlResolver origin, CancellationToken ct)
    {
        if (Caller(context) is not { } caller)
        {
            return Unauthorized();
        }

        int? limit = int.TryParse(context.Request.Query["limit"], out var parsed) ? parsed : null;
        return (await service.ListSharesAsync(caller, origin.Resolve(context.Request), limit, ct)).ToHttp(shares => Results.Json(new { shares }));
    }

    private static async Task<IResult> GetShareAsync(string token, HttpContext context, AgentShareService service, PublicBaseUrlResolver origin, CancellationToken ct) =>
        Caller(context) is { } caller ? (await service.GetShareAsync(caller, origin.Resolve(context.Request), token, ct)).ToHttp() : Unauthorized();

    private static async Task<IResult> ListFilesAsync(string token, HttpContext context, AgentShareService service, PublicBaseUrlResolver origin, CancellationToken ct) =>
        Caller(context) is { } caller ? (await service.ListFilesAsync(caller, origin.Resolve(context.Request), token, ct)).ToHttp() : Unauthorized();

    private static async Task<IResult> DownloadFileAsync(string token, string fileId, HttpContext context, AgentShareService service, CancellationToken ct)
    {
        if (Caller(context) is not { } caller)
        {
            return Unauthorized();
        }

        var opened = await service.OpenFileAsync(caller, token, fileId, ct);
        return opened.ToHttp(file => ServeFile(context.Response, file));
    }

    /// <summary>
    /// Stored original as an attachment under the user-content policy (nosniff, sandbox CSP, no caching). Not a
    /// download event: owner access, so recipients' counts and notifications stay meaningful.
    /// </summary>
    private static IResult ServeFile(HttpResponse response, ShareFileContent file)
    {
        ObjectResults.ApplyNoStore(response);
        response.Headers["Referrer-Policy"] = "no-referrer";
        if (file.Received)
        {
            response.Headers["X-Agora-Untrusted"] = "true";
        }

        return ObjectResults.UserContent(response, file.Content, file.FileName, forceAttachment: true);
    }

    private static async Task<IResult> PutUploadAsync(
        string ticket,
        HttpContext context,
        AgentTicketStore tickets,
        ShareManager manager,
        ScratchSpaceMonitor scratchSpace,
        UploadConcurrency concurrency,
        IOptions<AgoraOptions> options,
        CancellationToken ct)
    {
        // Read, not claimed: refusals below leave the URL usable.
        if (tickets.Peek(ticket) is not { Kind: AgentTicketStore.KindUpload } t)
        {
            return Refuse(StatusCodes.Status404NotFound, InvalidTicket);
        }

        if (context.Request.ContentLength is not { } length)
        {
            return Refuse(StatusCodes.Status411LengthRequired, "A Content-Length header with the file size is required.");
        }

        if (length != t.SizeBytes)
        {
            return Refuse(StatusCodes.Status413PayloadTooLarge, $"The body must be exactly {t.SizeBytes} bytes.");
        }

        var cfg = options.Value;
        Guid ownerUserId;
        string draftId;
        string[] keys;
        if (t.IsPublic)
        {
            if (context.RequestServices.GetService<IPublicDraftAdmission>() is not { } admission)
            {
                return Refuse(StatusCodes.Status404NotFound, InvalidTicket);
            }

            var admitted = await admission.AdmitAsync(t, context, ct);
            if (!admitted.IsOk)
            {
                return admitted.ToHttp();
            }

            ownerUserId = admitted.Value!.OwnerUserId;
            draftId = admitted.Value.DraftId;
            keys = [UploadConcurrency.AddressKey(UploadStagingEndpoints.ClientAddress(context)), UploadConcurrency.DraftKey(draftId)];
        }
        else
        {
            // An owner ticket lives and dies with the token that issued it (and its account).
            if (!await TokenStillWorksAsync(context, t, ct))
            {
                return Refuse(StatusCodes.Status404NotFound, InvalidTicket);
            }

            try
            {
                ownerUserId = t.OwnerUserId;
                draftId = await manager.EnsureDraftShareAsync(ownerUserId, t.DraftId, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Refuse(StatusCodes.Status400BadRequest, ex.Message);
            }
            catch (UploadLimitException ex)
            {
                return UploadStagingEndpoints.UploadLimitJson(ex);
            }

            keys = [UploadConcurrency.AccountKey(ownerUserId), UploadConcurrency.DraftKey(draftId)];
        }

        if (!concurrency.TryAdmit(context, keys))
        {
            return UploadConcurrency.TooManyJson();
        }

        var purpose = AgentStaging.PurposeToStorage(t.Purpose);
        if (await AgentStaging.CheckSizeAsync(manager, cfg, draftId, purpose, t.SizeBytes, ct) is { } tooBig)
        {
            return tooBig.ToHttp();
        }

        ScratchReservation reservation;
        try
        {
            reservation = scratchSpace.Reserve(ScratchDemand.Scratch(t.SizeBytes));
        }
        catch (UploadLimitException ex)
        {
            return UploadStagingEndpoints.UploadLimitJson(ex);
        }

        context.Response.RegisterForDispose(reservation);

        // Single use: from here on the URL is spent, whatever happens to the body.
        if (tickets.TryClaim(ticket) is null)
        {
            return Refuse(StatusCodes.Status404NotFound, InvalidTicket);
        }

        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySize)
        {
            bodySize.MaxRequestBodySize = t.SizeBytes;
        }

        UploadConcurrency.ApplyMinBodyDataRate(context);
        var path = ScratchFiles.NewPath(cfg.StorageRoot, ".agent-upload");
        try
        {
            await using (var scratch = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                if (!await CopyExactlyAsync(context.Request.Body, scratch, t.SizeBytes, ct))
                {
                    return Refuse(StatusCodes.Status400BadRequest, "The body was shorter than the announced size.");
                }
            }

            await using var source = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            var staged = await AgentStaging.StageAsync(manager, cfg, ownerUserId, draftId, t.FileName!, source, purpose, ct);
            return staged.ToHttp(info => Results.Json(info, statusCode: StatusCodes.Status201Created));
        }
        catch (BadHttpRequestException ex)
        {
            return Refuse(ex.StatusCode, "The request body could not be read.");
        }
        finally
        {
            ScratchFiles.TryDelete(path);
        }
    }

    private static async Task<IResult> GetDownloadAsync(string ticket, HttpContext context, AgentTicketStore tickets, AgentShareService service, CancellationToken ct)
    {
        const string invalid = "This download URL is invalid, expired or already used.";
        if (tickets.Peek(ticket) is not { Kind: AgentTicketStore.KindDownload, ShareToken: { } token, FileId: { } fileId } t)
        {
            return Refuse(StatusCodes.Status404NotFound, invalid);
        }

        // Downloads need level all at redemption too: a ticket issued before a downgrade stops working with it.
        var level = t.TokenId is { } issuer
            ? await context.RequestServices.GetRequiredService<Agora.Infrastructure.Auth.ApiTokenService>().ActiveAccessLevelAsync(issuer, t.OwnerUserId, ct)
            : null;
        if (level != ApiTokens.AccessLevels.All)
        {
            return Refuse(StatusCodes.Status404NotFound, invalid);
        }

        // Open first so a share that is gone does not burn the URL; then claim, so exactly one caller gets the bytes.
        var opened = await service.OpenFileAsync(t.OwnerUserId, token, fileId.ToString(), ct);
        if (!opened.IsOk)
        {
            return opened.ToHttp();
        }

        if (tickets.TryClaim(ticket) is null)
        {
            await opened.Value!.Content.Content.DisposeAsync();
            return Refuse(StatusCodes.Status404NotFound, invalid);
        }

        return ServeFile(context.Response, opened.Value!);
    }

    private static async Task<bool> TokenStillWorksAsync(HttpContext context, AgentTicketStore.Ticket ticket, CancellationToken ct) =>
        ticket.TokenId is { } tokenId &&
        await context.RequestServices.GetRequiredService<Agora.Infrastructure.Auth.ApiTokenService>().IsTokenActiveAsync(tokenId, ticket.OwnerUserId, ct);

    private static async Task<bool> CopyExactlyAsync(Stream source, Stream destination, long expected, CancellationToken ct)
    {
        var buffer = new byte[81920];
        long copied = 0;
        while (true)
        {
            var read = await source.ReadAsync(buffer, ct);
            if (read == 0)
            {
                return copied == expected;
            }

            copied += read;
            if (copied > expected)
            {
                throw new BadHttpRequestException("The body is larger than announced.", StatusCodes.Status413PayloadTooLarge);
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), ct);
        }
    }

    private static AgentCaller? Caller(HttpContext context) => AgentCaller.FromPrincipal(context.User);

    private static IResult Unauthorized() => Refuse(StatusCodes.Status401Unauthorized, "An agent API token is required.");

    private static IResult Refuse(int status, string error) => Results.Json(new { error }, statusCode: status);

    /// <summary>
    /// A JSON body of at most <paramref name="limit"/> bytes: 415 without a JSON content type, 413 when too large,
    /// 400 when malformed. Read by hand so the cap holds even where the server enforces no request size limit.
    /// </summary>
    public static async Task<(T? Value, IResult? Refusal)> ReadJsonAsync<T>(HttpRequest request, long limit, CancellationToken ct)
        where T : class
    {
        if (!request.HasJsonContentType())
        {
            return (null, Refuse(StatusCodes.Status415UnsupportedMediaType, "Send the request as application/json."));
        }

        if (request.ContentLength > limit)
        {
            return (null, Refuse(StatusCodes.Status413PayloadTooLarge, $"The request body is larger than {limit} bytes."));
        }

        using var buffer = new MemoryStream();
        try
        {
            var chunk = new byte[16 * 1024];
            int read;
            while ((read = await request.Body.ReadAsync(chunk, ct)) > 0)
            {
                if (buffer.Length + read > limit)
                {
                    return (null, Refuse(StatusCodes.Status413PayloadTooLarge, $"The request body is larger than {limit} bytes."));
                }

                buffer.Write(chunk, 0, read);
            }

            var value = JsonSerializer.Deserialize<T>(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), JsonOptions);
            return value is null ? (null, Refuse(StatusCodes.Status400BadRequest, "A JSON object is required.")) : (value, null);
        }
        catch (JsonException)
        {
            return (null, Refuse(StatusCodes.Status400BadRequest, "The request body is not valid JSON."));
        }
        catch (BadHttpRequestException ex)
        {
            return (null, Refuse(ex.StatusCode, "The request body could not be read."));
        }
    }
}
