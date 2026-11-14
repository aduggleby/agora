using System.Text.Json;
using System.Text.Json.Serialization;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Web.Services;
using Agora.Web.Startup;
using Microsoft.AspNetCore.Mvc;

namespace Agora.Web.Endpoints;

/// <summary>
/// The OAuth surface of the agent interface: discovery documents (RFC 9728 protected resource metadata at the path
/// form for <c>/mcp</c>, RFC 8414 authorization server metadata), stateless dynamic client registration (RFC 7591) and
/// the authorization code exchange (JSON as the capture app sends it, or form encoded as MCP clients send it). All of
/// it is anonymous, answers <c>no-store</c> and carries <see cref="ApiEndpointMetadata"/> (no cookies, no CSRF).
/// </summary>
public static class OAuthEndpoints
{
    public const string GrantTypeAuthorizationCode = "authorization_code";
    private const int MaxRequestBytes = 16 * 1024;

    public sealed record TokenRequest(
        [property: JsonPropertyName("grant_type")] string? GrantType,
        [property: JsonPropertyName("code")] string? Code,
        [property: JsonPropertyName("code_verifier")] string? CodeVerifier,
        [property: JsonPropertyName("redirect_uri")] string? RedirectUri,
        [property: JsonPropertyName("client_id")] string? ClientId,
        [property: JsonPropertyName("resource")] string? Resource = null);

    public sealed record RegistrationRequest(
        [property: JsonPropertyName("redirect_uris")] List<string>? RedirectUris,
        [property: JsonPropertyName("client_name")] string? ClientName);

    public static IEndpointRouteBuilder MapOAuthEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/oauth-protected-resource/mcp", ProtectedResourceMetadata)
            .WithMetadata(ApiEndpointMetadata.Instance).AllowAnonymous();
        app.MapGet("/.well-known/oauth-authorization-server", AuthorizationServerMetadata)
            .WithMetadata(ApiEndpointMetadata.Instance).AllowAnonymous();
        app.MapPost("/oauth/register", RegisterClientAsync)
            .WithMetadata(ApiEndpointMetadata.Instance, new RequestSizeLimitAttribute(MaxRequestBytes))
            .AllowAnonymous()
            .DisableAntiforgery()
            .RequireRateLimiting(RateLimitSetup.AuthEndpoints);
        app.MapPost("/api/v1/auth/token", ExchangeTokenAsync)
            .WithMetadata(ApiEndpointMetadata.Instance, new RequestSizeLimitAttribute(MaxRequestBytes))
            .AllowAnonymous()
            .DisableAntiforgery()
            .RequireRateLimiting(RateLimitSetup.AuthEndpoints);
        return app;
    }

    private static IResult ProtectedResourceMetadata(HttpContext context, PublicBaseUrlResolver publicBaseUrls)
    {
        NoStore(context);
        var baseUrl = publicBaseUrls.Resolve(context.Request);
        return Results.Json(new
        {
            resource = baseUrl + "/mcp",
            authorization_servers = new[] { baseUrl },
            bearer_methods_supported = new[] { "header" },
            resource_name = "Agora"
        });
    }

    private static IResult AuthorizationServerMetadata(HttpContext context, PublicBaseUrlResolver publicBaseUrls)
    {
        NoStore(context);
        var baseUrl = publicBaseUrls.Resolve(context.Request);
        return Results.Json(new
        {
            issuer = baseUrl,
            authorization_endpoint = baseUrl + "/connect/authorize",
            token_endpoint = baseUrl + "/api/v1/auth/token",
            registration_endpoint = baseUrl + "/oauth/register",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { GrantTypeAuthorizationCode },
            code_challenge_methods_supported = new[] { ApiTokens.CodeChallengeMethod },
            token_endpoint_auth_methods_supported = new[] { "none" }
        });
    }

    private static async Task<IResult> RegisterClientAsync(HttpContext context, OAuthClientCodec codec, CancellationToken ct)
    {
        NoStore(context);
        if (!context.Request.HasJsonContentType())
        {
            return RegistrationError("invalid_client_metadata", "Send the request as application/json.");
        }

        RegistrationRequest? body;
        try
        {
            body = await context.Request.ReadFromJsonAsync<RegistrationRequest>(ct);
        }
        catch (JsonException)
        {
            return RegistrationError("invalid_client_metadata", "The request body is not valid JSON.");
        }
        catch (BadHttpRequestException)
        {
            return RegistrationError("invalid_client_metadata", "The request body is too large or could not be read.");
        }

        var uris = body?.RedirectUris;
        if (uris is not { Count: > 0 and <= OAuthClients.MaxRedirectUris })
        {
            return RegistrationError("invalid_redirect_uri", $"Send 1 to {OAuthClients.MaxRedirectUris} redirect_uris.");
        }

        if (uris.Any(x => !OAuthClients.IsAllowedRedirectUri(x, codec.AllowedRedirectHosts)))
        {
            return RegistrationError("invalid_redirect_uri",
                "Each redirect URI must be an http loopback address (127.0.0.1, [::1] or localhost) or an https address on a trusted host, without query or fragment.");
        }

        if (body!.ClientName is { Length: > OAuthClients.MaxClientNameLength })
        {
            return RegistrationError("invalid_client_metadata", $"client_name is longer than {OAuthClients.MaxClientNameLength} characters.");
        }

        var name = ApiTokens.SanitizeDeviceName(body.ClientName);
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var clientId = codec.Encode(new OAuthClientRegistration(name, uris.Distinct(StringComparer.Ordinal).ToList(), issuedAt));
        return Results.Json(new
        {
            client_id = clientId,
            client_id_issued_at = issuedAt,
            client_name = name,
            redirect_uris = uris,
            grant_types = new[] { GrantTypeAuthorizationCode },
            response_types = new[] { "code" },
            token_endpoint_auth_method = "none"
        }, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> ExchangeTokenAsync(
        HttpContext context,
        ApiTokenService tokens,
        OAuthClientCodec codec,
        PublicBaseUrlResolver publicBaseUrls,
        CancellationToken ct)
    {
        NoStore(context);
        context.Response.Headers.Pragma = "no-cache";
        TokenRequest? body;
        if (context.Request.HasJsonContentType())
        {
            try
            {
                body = await context.Request.ReadFromJsonAsync<TokenRequest>(ct);
            }
            catch (JsonException)
            {
                return TokenError("invalid_request", "The request body is not valid JSON.");
            }
            catch (BadHttpRequestException)
            {
                return TokenError("invalid_request", "The request body is too large or could not be read.");
            }
        }
        else if (context.Request.HasFormContentType)
        {
            try
            {
                var form = await context.Request.ReadFormAsync(ct);
                if (form.Any(x => x.Value.Count > 1))
                {
                    return TokenError("invalid_request", "A parameter was sent more than once.");
                }

                body = new TokenRequest(
                    form["grant_type"], form["code"], form["code_verifier"], form["redirect_uri"], form["client_id"], form["resource"]);
            }
            catch (Exception ex) when (ex is InvalidDataException or BadHttpRequestException or IOException)
            {
                return TokenError("invalid_request", "The request body is too large or could not be read.");
            }
        }
        else
        {
            return TokenError("invalid_request", "Send the request as application/json.");
        }

        if (body is null || string.IsNullOrWhiteSpace(body.GrantType))
        {
            return TokenError("invalid_request", "grant_type is required.");
        }

        if (!string.Equals(body.GrantType, GrantTypeAuthorizationCode, StringComparison.Ordinal))
        {
            return TokenError("unsupported_grant_type", "Only authorization_code is supported.");
        }

        var isMcpClient = OAuthClients.IsMcpClientId(body.ClientId);
        if (string.IsNullOrWhiteSpace(body.Code) || string.IsNullOrWhiteSpace(body.CodeVerifier) ||
            string.IsNullOrWhiteSpace(body.ClientId) || (!isMcpClient && string.IsNullOrWhiteSpace(body.RedirectUri)))
        {
            return TokenError("invalid_request", "code, code_verifier, redirect_uri and client_id are required.");
        }

        var storedClientId = body.ClientId;
        if (isMcpClient)
        {
            if (codec.Decode(body.ClientId) is null)
            {
                return TokenError("invalid_client", "The client registration is not valid here; register the client again.");
            }

            storedClientId = OAuthClients.StoredClientId(body.ClientId);
        }
        else if (!string.Equals(body.ClientId, ApiTokens.CaptureClientId, StringComparison.Ordinal))
        {
            return TokenError("invalid_request", "Unknown client_id.");
        }

        if (!string.IsNullOrEmpty(body.Resource) && !OAuthClients.IsValidResource(body.Resource, publicBaseUrls.Resolve(context.Request)))
        {
            return TokenError("invalid_target", "The resource is not served by this server.");
        }

        var result = await tokens.ExchangeAsync(body.Code, body.CodeVerifier, body.RedirectUri, storedClientId, ct);
        if (!result.Success)
        {
            return TokenError(result.Error ?? ApiTokenExchangeResult.InvalidGrant, result.Error == ApiTokenExchangeResult.InvalidRequest
                ? "The request is missing a required parameter."
                : "The authorization code is invalid, expired or already used, or does not match this request.");
        }

        return Results.Ok(new
        {
            access_token = result.AccessToken,
            token_type = "Bearer",
            token_id = result.TokenId,
            email = result.Email
        });
    }

    private static void NoStore(HttpContext context) => context.Response.Headers.CacheControl = "no-store";

    private static IResult TokenError(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: StatusCodes.Status400BadRequest);

    private static IResult RegistrationError(string error, string description) => TokenError(error, description);
}
