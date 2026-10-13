using Agora.Web.Auth;
using Agora.Web.Endpoints;
using Microsoft.AspNetCore.Antiforgery;

namespace Agora.Web.Startup;

/// <summary>
/// Antiforgery for the whole site: safe methods get the request token as a readable cookie for the bundled CSRF
/// client, unsafe methods are validated (except the E2E test routes and the Hangfire dashboard). Endpoints marked
/// with <see cref="UploadEndpointMetadata"/> that require the header token are refused before anything reads the form,
/// because the antiforgery form fallback would otherwise buffer the multipart body ahead of every admission check.
/// </summary>
public static class CsrfValidation
{
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string RequestTokenCookieName = "agora.csrf.request";

    public static IApplicationBuilder UseAgoraCsrf(this IApplicationBuilder app, bool isE2E, CookieSecurePolicy cookieSecurePolicy, ILogger logger)
    {
        return app.Use(async (context, next) =>
        {
            // Health probes stay independent of DataProtection/antiforgery and never set cookies.
            if (IsHealthPath(context.Request.Path))
            {
                await next();
                return;
            }

            var antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();

            if (IsSafeHttpMethod(context.Request.Method))
            {
                var tokens = antiforgery.GetAndStoreTokens(context);
                if (!string.IsNullOrWhiteSpace(tokens.RequestToken))
                {
                    context.Response.Cookies.Append(RequestTokenCookieName, tokens.RequestToken, new CookieOptions
                    {
                        HttpOnly = false,
                        SameSite = SameSiteMode.Lax,
                        Secure = CookieSessions.IsSecure(cookieSecurePolicy, context.Request.IsHttps),
                        Path = "/"
                    });
                }

                await next();
                return;
            }

            if (isE2E && context.Request.Path.StartsWithSegments("/api/e2e", StringComparison.OrdinalIgnoreCase))
            {
                await next();
                return;
            }

            if (context.Request.Path.StartsWithSegments("/hangfire", StringComparison.OrdinalIgnoreCase))
            {
                await next();
                return;
            }

            var uploadEndpoint = context.GetEndpoint()?.Metadata.GetMetadata<UploadEndpointMetadata>();
            if (uploadEndpoint is { RequiresHeaderCsrfToken: true } && string.IsNullOrWhiteSpace(context.Request.Headers[HeaderName]))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new { error = $"Send the CSRF token in the {HeaderName} header." });
                return;
            }

            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException ex)
            {
                // Route pattern and Referer origin only: paths such as /s/{token}/download and referring share
                // pages carry tokens.
                logger.LogWarning(
                    ex,
                    "CSRF validation failed for {Method} {Route}. IsHttps={IsHttps} Host={Host} Origin={Origin} RefererOrigin={RefererOrigin}",
                    context.Request.Method,
                    (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? context.GetEndpoint()?.DisplayName ?? "<unmatched>",
                    context.Request.IsHttps,
                    context.Request.Host.Value,
                    context.Request.Headers.Origin.ToString(),
                    RefererOrigin(context.Request.Headers.Referer.ToString()));
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new { error = "Invalid or missing CSRF token." });
                return;
            }

            await next();
        });
    }

    private static bool IsHealthPath(PathString path) =>
        path.Equals("/live", StringComparison.OrdinalIgnoreCase) || path.Equals("/ready", StringComparison.OrdinalIgnoreCase);

    private static bool IsSafeHttpMethod(string method) =>
        HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method) || HttpMethods.IsTrace(method);

    private static string RefererOrigin(string referer)
    {
        if (string.IsNullOrWhiteSpace(referer))
        {
            return "<none>";
        }

        return Uri.TryCreate(referer, UriKind.Absolute, out var uri)
            ? uri.GetLeftPart(UriPartial.Authority)
            : "<invalid>";
    }
}
