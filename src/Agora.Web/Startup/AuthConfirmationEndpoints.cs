using Agora.Infrastructure.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Agora.Web.Startup;

/// <summary>
/// The GET endpoints behind emailed confirmation links. They consume single-use tokens, so like the sign-in and
/// registration handlers they are limited per client IP with the <see cref="RateLimitSetup.AuthEndpoints"/> policy.
/// </summary>
public static class AuthConfirmationEndpoints
{
    public static IEndpointRouteBuilder MapAuthConfirmationEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/confirm-email", async (AuthService authService, string email, string token, CancellationToken ct) =>
        {
            var result = await authService.ConfirmEmailAsync(email, token, ct);
            return Results.Redirect(result.Success
                ? "/login?msg=Email%20confirmed.%20You%20can%20now%20sign%20in"
                : $"/login?msg={Uri.EscapeDataString(result.Error)}");
        }).RequireRateLimiting(RateLimitSetup.AuthEndpoints);

        app.MapGet("/auth/confirm-email-change", async (HttpContext context, AuthService authService, string email, string token, CancellationToken ct) =>
        {
            var result = await authService.ConfirmEmailChangeAsync(email, token, ct);
            if (!result.Success)
            {
                return Results.Redirect($"/account/settings?msg={Uri.EscapeDataString(result.Error)}");
            }

            if (context.User.Identity?.IsAuthenticated == true)
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            return Results.Redirect("/login?msg=Email%20updated.%20Please%20sign%20in%20again");
        }).RequireRateLimiting(RateLimitSetup.AuthEndpoints);

        app.MapGet("/auth/confirm-password-change", async (HttpContext context, AuthService authService, string email, string token, CancellationToken ct) =>
        {
            var result = await authService.ConfirmPasswordChangeAsync(email, token, ct);
            if (context.User.Identity?.IsAuthenticated == true)
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            }

            return Results.Redirect(result.Success
                ? "/login?msg=Password%20updated.%20Please%20sign%20in%20again"
                : $"/login?msg={Uri.EscapeDataString(result.Error)}");
        }).RequireRateLimiting(RateLimitSetup.AuthEndpoints);

        return app;
    }
}
