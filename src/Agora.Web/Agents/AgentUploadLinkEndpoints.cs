using Agora.Web.Endpoints;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;

namespace Agora.Web.Agents;

/// <summary>
/// The anonymous agent API of an upload link under <c>/api/v1/upload-links/{code}</c>. Every route resolves the code,
/// then the owner's agent switch, before it reads anything; shares the browser's public-upload rate bucket; carries
/// <see cref="ApiEndpointMetadata"/> (no cookies, no CSRF); and requires JSON bodies (415 otherwise). The inline
/// routes parse at most 2 MiB, after the middleware admitted at most two such requests per address.
/// </summary>
public static class AgentUploadLinkEndpoints
{
    private const long SmallBodyLimit = 64 * 1024;

    public static IEndpointRouteBuilder MapAgentUploadLinkEndpoints(this IEndpointRouteBuilder app)
    {
        var links = app.MapGroup("/api/v1/upload-links/{code}")
            .WithMetadata(ApiEndpointMetadata.Instance)
            .AllowAnonymous()
            .DisableAntiforgery()
            .RequireRateLimiting(RateLimitSetup.PublicUploadEndpoints);

        links.MapGet("", DescribeAsync);
        links.MapPost("/uploads", UploadAsync)
            .WithMetadata(new AgentUploadRouteMetadata(InlineBody: true), new RequestSizeLimitAttribute(AgentLimits.InlineRequestBodyLimit));
        links.MapPost("/upload-urls", IssueUploadUrlAsync)
            .WithMetadata(new RequestSizeLimitAttribute(SmallBodyLimit));
        links.MapPost("/send", SendAsync)
            .WithMetadata(new AgentUploadRouteMetadata(InlineBody: true), new RequestSizeLimitAttribute(AgentLimits.InlineRequestBodyLimit));
        return app;
    }

    private sealed record UploadBody(string? DraftId, string? FileName, string? Text, string? ContentBase64);

    private sealed record UploadUrlBody(string? DraftId, string? FileName, long SizeBytes);

    private sealed record SendBody(
        string? DraftId, IReadOnlyList<InlineFile>? Files, IReadOnlyList<string>? FileIds, string? SenderName, string? SenderEmail, string? Message);

    private static async Task<IResult> DescribeAsync(string code, HttpContext context, AgentUploadLinkService service, PublicBaseUrlResolver origin, CancellationToken ct) =>
        (await service.DescribeAsync(code, origin.Resolve(context.Request), ct)).ToHttp();

    private static async Task<IResult> UploadAsync(string code, HttpContext context, AgentUploadLinkService service, PublicBaseUrlResolver origin, CancellationToken ct)
    {
        var baseUrl = origin.Resolve(context.Request);
        if (await Gate(service, code, baseUrl, ct) is { } refused)
        {
            return refused;
        }

        var (body, refusal) = await AgentOwnerEndpoints.ReadJsonAsync<UploadBody>(context.Request, AgentLimits.InlineRequestBodyLimit, ct);
        return refusal ?? (await service.UploadInlineAsync(code, baseUrl, Address(context), body!.DraftId, new InlineFile(body.FileName, body.Text, body.ContentBase64), ct)).ToHttp();
    }

    private static async Task<IResult> IssueUploadUrlAsync(string code, HttpContext context, AgentUploadLinkService service, PublicBaseUrlResolver origin, CancellationToken ct)
    {
        var baseUrl = origin.Resolve(context.Request);
        if (await Gate(service, code, baseUrl, ct) is { } refused)
        {
            return refused;
        }

        var (body, refusal) = await AgentOwnerEndpoints.ReadJsonAsync<UploadUrlBody>(context.Request, SmallBodyLimit, ct);
        return refusal ?? (await service.IssueUploadUrlAsync(code, baseUrl, Address(context), body!.DraftId, body.FileName, body.SizeBytes, ct)).ToHttp();
    }

    private static async Task<IResult> SendAsync(string code, HttpContext context, AgentUploadLinkService service, PublicBaseUrlResolver origin, CancellationToken ct)
    {
        var baseUrl = origin.Resolve(context.Request);
        if (await Gate(service, code, baseUrl, ct) is { } refused)
        {
            return refused;
        }

        var (body, refusal) = await AgentOwnerEndpoints.ReadJsonAsync<SendBody>(context.Request, AgentLimits.InlineRequestBodyLimit, ct);
        if (refusal is not null)
        {
            return refusal;
        }

        var result = await service.SendAsync(code, baseUrl, Address(context),
            new SendFilesRequest(body!.DraftId, body.Files, body.FileIds, body.SenderName, body.SenderEmail, body.Message), ct);
        return result.ToHttp();
    }

    /// <summary>Code, then switch: before the content type or body is looked at.</summary>
    private static async Task<IResult?> Gate(AgentUploadLinkService service, string code, string baseUrl, CancellationToken ct)
    {
        var owner = await service.ResolveAsync(code, baseUrl, ct);
        return owner.IsOk ? null : owner.ToHttp();
    }

    private static string Address(HttpContext context) => UploadStagingEndpoints.ClientAddress(context);
}
