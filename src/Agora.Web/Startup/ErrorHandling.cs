namespace Agora.Web.Startup;

/// <summary>
/// Turns an unhandled exception into a plain 500 written inside the pipeline. Without it the server drops the
/// response and skips every <c>OnStarting</c> callback, so the security headers would be missing on that response.
/// Not used in Development, which keeps the developer exception page.
/// </summary>
public static class ErrorHandling
{
    public const string Body = "Something went wrong.";

    public static IApplicationBuilder UseAgoraExceptionHandler(this IApplicationBuilder app) =>
        app.UseExceptionHandler(errors => errors.Run(async context =>
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync(Body, context.RequestAborted);
        }));
}
