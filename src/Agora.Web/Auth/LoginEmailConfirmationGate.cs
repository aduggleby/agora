using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace Agora.Web.Auth;

internal static class LoginEmailConfirmationGate
{
    private const string Purpose = "agora.login.email-confirmation-required";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    public static string Create(IDataProtectionProvider provider, string email)
    {
        var protector = provider.CreateProtector(Purpose).ToTimeLimitedDataProtector();
        var payload = protector.Protect(email.Trim(), Lifetime);
        return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
    }

    public static bool TryRead(IDataProtectionProvider provider, string? gateToken, out string email)
    {
        email = string.Empty;
        if (string.IsNullOrWhiteSpace(gateToken))
        {
            return false;
        }

        byte[] rawPayload;
        try
        {
            rawPayload = WebEncoders.Base64UrlDecode(gateToken);
        }
        catch
        {
            return false;
        }

        var payload = Encoding.UTF8.GetString(rawPayload);
        var protector = provider.CreateProtector(Purpose).ToTimeLimitedDataProtector();

        try
        {
            var unprotected = protector.Unprotect(payload, out var expiresAtUtc);
            if (expiresAtUtc <= DateTimeOffset.UtcNow)
            {
                return false;
            }

            email = unprotected.Trim();
            return !string.IsNullOrWhiteSpace(email);
        }
        catch
        {
            return false;
        }
    }
}
