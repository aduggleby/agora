using Agora.Web.Auth;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Agora.Web.Endpoints;

/// <summary>
/// The "password entered" state of a password-protected share page: a time-limited, DataProtection-protected cookie
/// that names the share it unlocks. Until it is present the page and <c>/s/{token}/background</c> reveal nothing about
/// the share. The cookie path scopes it to the share's routes, but path matching is prefix-based, so the share id in
/// the payload is what binds it. The cookie never contains the password: the archive is encrypted with it, so the
/// download form still asks for it.
/// </summary>
public static class ShareUnlockGate
{
    public const string CookieName = "agora.share.unlock";
    public const string Purpose = "agora.share.unlock";
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(4);

    public static void Grant(HttpContext context, Guid shareId, string token)
    {
        var protector = Protector(context);
        var value = protector.Protect(shareId.ToString("N"), Lifetime);
        // The Secure policy is the one Program.cs gives the antiforgery cookie (Agora:Auth:SecureCookies), read from
        // there so this cookie follows the same rule without its own configuration.
        var securePolicy = context.RequestServices.GetRequiredService<IOptions<AntiforgeryOptions>>().Value.Cookie.SecurePolicy;
        context.Response.Cookies.Append(CookieName, value, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = CookieSessions.IsSecure(securePolicy, context.Request.IsHttps),
            Path = $"/s/{Uri.EscapeDataString(token)}",
            MaxAge = Lifetime
        });
    }

    public static bool IsUnlocked(HttpContext context, Guid shareId)
    {
        var value = context.Request.Cookies[CookieName];
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        try
        {
            var payload = Protector(context).Unprotect(value, out var expiresAt);
            return expiresAt > DateTimeOffset.UtcNow && string.Equals(payload, shareId.ToString("N"), StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static ITimeLimitedDataProtector Protector(HttpContext context) =>
        context.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).ToTimeLimitedDataProtector();
}
