using System.Buffers.Text;
using System.Security.Cryptography;
using Agora.Application.Models;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Options;

namespace Agora.Web.Startup;

/// <summary>
/// Browser hardening headers on every response (unless the response already carries them) and a report-only CSP
/// with a per-request script nonce on the app's own HTML pages. User-content responses keep their enforced
/// <see cref="Endpoints.ObjectResults.UserContentCsp"/>; the Hangfire dashboard renders its own inline scripts and
/// is left without the report-only policy. <c>Agora:SecurityHeaders:Enabled=false</c> turns the middleware off for
/// operators who set the headers at the proxy.
/// </summary>
public static class SecurityHeaders
{
    public const string NonceItemKey = "csp-nonce";
    public const string ReportOnlyHeaderName = "Content-Security-Policy-Report-Only";
    public const string HstsValue = "max-age=31536000; includeSubDomains";

    /// <summary>
    /// Report-only policy for HTML pages. Scripts are bundled locally (SignalR and Alpine included), so script-src is
    /// self plus the nonce. Google Fonts is the only third-party asset. style-src keeps 'unsafe-inline' for the
    /// inline styles of the self-contained public pages; inline event handlers and Alpine expressions are reported.
    /// </summary>
    public static string ReportOnlyPolicy(string nonce) =>
        "default-src 'self'; " +
        $"script-src 'self' 'nonce-{nonce}'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "img-src 'self' data: blob:; " +
        "media-src 'self' blob:; " +
        "connect-src 'self'; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "frame-ancestors 'self'; " +
        "form-action 'self'; " +
        "base-uri 'self'; " +
        "object-src 'none'";

    private static readonly (string Name, string Value)[] FixedHeaders =
    [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    ];

    public static IApplicationBuilder UseAgoraSecurityHeaders(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<IOptions<AgoraOptions>>().Value.SecurityHeaders;
        if (!options.Enabled)
        {
            return app;
        }

        return app.Use(async (context, next) =>
        {
            context.Items[NonceItemKey] = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
            context.Response.OnStarting(static state =>
            {
                Apply((HttpContext)state);
                return Task.CompletedTask;
            }, context);
            await next();
        });
    }

    /// <summary>Nonce of the current request for <c>&lt;script nonce&gt;</c>; empty when the middleware is off.</summary>
    public static string CspNonce(this IHtmlHelper html) =>
        html.ViewContext.HttpContext.Items[NonceItemKey] as string ?? string.Empty;

    private static void Apply(HttpContext context)
    {
        var headers = context.Response.Headers;
        foreach (var (name, value) in FixedHeaders)
        {
            if (!headers.ContainsKey(name))
            {
                headers[name] = value;
            }
        }

        if (context.Request.IsHttps && !headers.ContainsKey("Strict-Transport-Security"))
        {
            headers["Strict-Transport-Security"] = HstsValue;
        }

        if (WantsReportOnlyPolicy(context) && context.Items[NonceItemKey] is string nonce)
        {
            headers[ReportOnlyHeaderName] = ReportOnlyPolicy(nonce);
        }
    }

    private static bool WantsReportOnlyPolicy(HttpContext context)
    {
        var headers = context.Response.Headers;
        if (headers.ContainsKey("Content-Security-Policy") || headers.ContainsKey(ReportOnlyHeaderName))
        {
            return false;
        }

        if (!headers.ContentType.ToString().StartsWith("text/html", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !context.Request.Path.StartsWithSegments("/hangfire", StringComparison.OrdinalIgnoreCase);
    }
}
