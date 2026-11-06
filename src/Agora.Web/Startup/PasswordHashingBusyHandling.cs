using System.Globalization;
using Agora.Infrastructure.Auth;

namespace Agora.Web.Startup;

/// <summary>
/// Answers <see cref="PasswordHashingBusyException"/> (every password-hashing slot busy) with 503 and
/// <c>Retry-After</c>. Form posts of the sign-in pages go back to their page with the message instead, and share-page
/// password posts (<c>/s/{token}/download</c>, <c>/s/{token}/unlock</c>) go back to the share page with
/// <c>?downloadError=busy</c>, so the user sees a friendly note rather than an error page.
/// </summary>
public static class PasswordHashingBusyHandling
{
    /// <summary>Form posts that redirect back to a page showing <c>?msg=</c>.</summary>
    private static readonly Dictionary<string, string> FormReturnPages = new(StringComparer.OrdinalIgnoreCase)
    {
        ["/login"] = "/login",
        ["/register"] = "/register",
        ["/auth/resend-confirmation"] = "/login",
        ["/forgot-password"] = "/forgot-password",
    };

    public static IApplicationBuilder UsePasswordHashingBusyHandling(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            try
            {
                await next(context);
            }
            catch (PasswordHashingBusyException) when (!context.Response.HasStarted)
            {
                await WriteBusyAsync(context);
            }
        });

    internal static Task WriteBusyAsync(HttpContext context)
    {
        var message = PasswordHashingBusyException.BusyMessage;
        context.Response.Clear();
        if (HttpMethods.IsPost(context.Request.Method) &&
            context.Request.HasFormContentType &&
            FormReturnPages.TryGetValue(context.Request.Path.Value ?? string.Empty, out var page))
        {
            context.Response.Redirect($"{page}?msg={Uri.EscapeDataString(message)}");
            return Task.CompletedTask;
        }

        if (HttpMethods.IsPost(context.Request.Method) && TryGetSharePasswordPostToken(context.Request.Path, out var token))
        {
            context.Response.Redirect($"/s/{Uri.EscapeDataString(token)}?downloadError=busy");
            return Task.CompletedTask;
        }

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = PasswordHashingBusyException.RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            return context.Response.WriteAsJsonAsync(new { error = message }, context.RequestAborted);
        }

        context.Response.ContentType = "text/plain; charset=utf-8";
        return context.Response.WriteAsync(message, context.RequestAborted);
    }

    /// <summary>Matches <c>/s/{token}/download</c> and <c>/s/{token}/unlock</c> and returns the (unescaped) token.</summary>
    private static bool TryGetSharePasswordPostToken(PathString path, out string token)
    {
        token = string.Empty;
        var segments = (path.Value ?? string.Empty).Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 3 || !string.Equals(segments[0], "s", StringComparison.Ordinal) ||
            !(string.Equals(segments[2], "download", StringComparison.Ordinal) || string.Equals(segments[2], "unlock", StringComparison.Ordinal)))
        {
            return false;
        }

        token = segments[1];
        return token.Length > 0;
    }
}
