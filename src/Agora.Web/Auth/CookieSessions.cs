using System.Globalization;
using System.Security.Claims;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Agora.Web.Auth;

public enum SessionCheck
{
    /// <summary>The user record still matches the cookie; re-issue the cookie with fresh claims.</summary>
    Refresh,

    /// <summary>The user is gone, disabled, or the security stamp no longer matches; end the session.</summary>
    Reject
}

/// <summary>
/// The single place that turns a <see cref="UserAccount"/> into the sign-in cookie principal, and the cookie
/// revalidation that compares that principal with the current user record at most every
/// <see cref="AgoraAuthOptions.SessionRevalidationMinutes"/>.
/// </summary>
public static class CookieSessions
{
    public const string SecurityStampClaim = "agora:security_stamp";
    public const string RevalidatedAtClaim = "agora:revalidated_at";

    public static ClaimsPrincipal CreatePrincipal(UserAccount user) => CreatePrincipal(user, DateTime.UtcNow);

    public static ClaimsPrincipal CreatePrincipal(UserAccount user, DateTime nowUtc)
    {
        var displayName = string.IsNullOrWhiteSpace(user.DisplayName) ? user.Email : user.DisplayName.Trim();
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, displayName),
            new(ClaimTypes.Role, user.Role),
            new(SecurityStampClaim, user.SecurityStamp),
            new(RevalidatedAtClaim, nowUtc.ToString("O", CultureInfo.InvariantCulture))
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        return new ClaimsPrincipal(identity);
    }

    public static TimeSpan RevalidationInterval(AgoraAuthOptions options) =>
        TimeSpan.FromMinutes(Math.Max(0, options.SessionRevalidationMinutes));

    public static TimeSpan SessionLifetime(AgoraAuthOptions options) =>
        TimeSpan.FromDays(Math.Max(1, options.SessionLifetimeDays));

    /// <summary>
    /// Secure flag policy shared by the sign-in cookie, the antiforgery cookie and the readable CSRF request cookie.
    /// <see cref="SecureCookiesMode.Auto"/> means Always in Production and SameAsRequest elsewhere.
    /// </summary>
    public static CookieSecurePolicy SecurePolicy(AgoraAuthOptions options, bool isProduction) => options.SecureCookies switch
    {
        SecureCookiesMode.Always => CookieSecurePolicy.Always,
        SecureCookiesMode.SameAsRequest => CookieSecurePolicy.SameAsRequest,
        _ => isProduction ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest
    };

    /// <summary>The Secure flag for a cookie appended by hand under <paramref name="policy"/>.</summary>
    public static bool IsSecure(CookieSecurePolicy policy, bool isHttps) => policy == CookieSecurePolicy.Always || isHttps;

    /// <summary>
    /// The timestamp of the last successful revalidation as stored in the cookie, or null when the principal has no
    /// usable one (pre-stamp cookie or tampering).
    /// </summary>
    public static DateTime? RevalidatedAt(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(RevalidatedAtClaim);
        return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var revalidatedAt)
            ? revalidatedAt.ToUniversalTime()
            : null;
    }

    /// <summary>
    /// True when the interval since the last check has passed, there was no usable last check, or the last check lies
    /// in the future (a timestamp in the future is distrusted).
    /// </summary>
    public static bool IsRevalidationDue(DateTime? revalidatedAtUtc, DateTime nowUtc, TimeSpan interval) =>
        revalidatedAtUtc is not { } at || at > nowUtc || nowUtc - at >= interval;

    public static bool IsRevalidationDue(ClaimsPrincipal principal, DateTime nowUtc, TimeSpan interval) =>
        IsRevalidationDue(RevalidatedAt(principal), nowUtc, interval);

    /// <summary>
    /// Decides what to do with a cookie whose revalidation is due, given the user record it names (or null when
    /// no such user exists). Pre-stamp cookies carry no stamp claim and are rejected.
    /// </summary>
    public static SessionCheck Validate(ClaimsPrincipal principal, UserAccount? user)
    {
        if (user is null || !user.IsEnabled)
        {
            return SessionCheck.Reject;
        }

        var cookieStamp = principal.FindFirstValue(SecurityStampClaim);
        if (string.IsNullOrEmpty(cookieStamp) || string.IsNullOrEmpty(user.SecurityStamp))
        {
            return SessionCheck.Reject;
        }

        return string.Equals(cookieStamp, user.SecurityStamp, StringComparison.Ordinal)
            ? SessionCheck.Refresh
            : SessionCheck.Reject;
    }

    /// <summary>Loads the user named by the principal's id claim without tracking, or null.</summary>
    public static Task<UserAccount?> LoadUserAsync(AgoraDbContext db, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        return Guid.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId)
            ? db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, cancellationToken)
            : Task.FromResult<UserAccount?>(null);
    }

    /// <summary>
    /// Runs the revalidation decision for the current principal: loads the user and validates the stamp. Returns the
    /// user on <see cref="SessionCheck.Refresh"/> and null on <see cref="SessionCheck.Reject"/>.
    /// </summary>
    public static async Task<UserAccount?> CheckAsync(AgoraDbContext db, ClaimsPrincipal principal, CancellationToken cancellationToken)
    {
        var user = await LoadUserAsync(db, principal, cancellationToken);
        return user is not null && Validate(principal, user) == SessionCheck.Refresh ? user : null;
    }

    public static DateTime NowUtc(IServiceProvider services) =>
        (services.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow().UtcDateTime;

    public static TimeSpan RevalidationInterval(IServiceProvider services) =>
        RevalidationInterval(services.GetRequiredService<IOptions<AgoraOptions>>().Value.Auth);

    /// <summary>
    /// Re-issues the cookie of an already signed-in user from the database record (role, name, stamp). The current
    /// cookie must still carry the user's live security stamp, regardless of whether its revalidation is due: a stale
    /// cookie (for example one stolen before a password reset) must never be laundered into a fresh one. On failure
    /// the session is signed out and false is returned.
    /// </summary>
    public static async Task<bool> TryReissueAsync(HttpContext httpContext, AgoraDbContext db, CancellationToken cancellationToken)
    {
        var user = await CheckAsync(db, httpContext.User, cancellationToken);
        if (user is null)
        {
            await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return false;
        }

        var nowUtc = NowUtc(httpContext.RequestServices);
        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, CreatePrincipal(user, nowUtc));
        return true;
    }

    public static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        var principal = context.Principal;
        if (principal is null)
        {
            return;
        }

        var services = context.HttpContext.RequestServices;
        var nowUtc = NowUtc(services);
        if (!IsRevalidationDue(principal, nowUtc, RevalidationInterval(services)))
        {
            return;
        }

        var user = await CheckAsync(services.GetRequiredService<AgoraDbContext>(), principal, context.HttpContext.RequestAborted);
        if (user is null)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }

        // Always re-issue so the role and name claims follow the database and the timestamp advances.
        context.ReplacePrincipal(CreatePrincipal(user, nowUtc));
        context.ShouldRenew = true;
    }
}
