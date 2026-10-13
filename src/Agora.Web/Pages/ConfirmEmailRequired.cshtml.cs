using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Web.Auth;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Agora.Web.Pages;

public class ConfirmEmailRequiredModel(
    AuthService authService,
    IOptions<AgoraOptions> options,
    IDataProtectionProvider dataProtectionProvider) : PageModel
{
    public string Email { get; private set; } = string.Empty;
    public string GateToken { get; private set; } = string.Empty;

    public IActionResult OnGet(string email, string gate, string? msg = null)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return Redirect("/");
        }

        if (!TryBindGate(email, gate))
        {
            return RedirectToPage("/Login");
        }

        ViewData["Title"] = "Confirm your email";
        ViewData["Message"] = msg ?? string.Empty;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string email, string gate, CancellationToken ct)
    {
        if (!TryBindGate(email, gate))
        {
            return RedirectToPage("/Login");
        }

        var publicBaseUrl = ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request);
        var confirmUrlBase = $"{publicBaseUrl}/auth/confirm-email";
        await authService.ResendEmailConfirmationAsync(Email, confirmUrlBase, ct);

        return RedirectToPage("/ConfirmEmailRequired", new
        {
            email = Email,
            gate = GateToken,
            msg = "If the account is unconfirmed, a confirmation email was sent"
        });
    }

    private bool TryBindGate(string email, string gate)
    {
        if (!LoginEmailConfirmationGate.TryRead(dataProtectionProvider, gate, out var gateEmail))
        {
            return false;
        }

        if (!string.Equals(gateEmail, email?.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        Email = gateEmail;
        GateToken = gate;
        return true;
    }

    private static string ResolvePublicBaseUrl(string? configuredValue, HttpRequest request)
    {
        var configured = (configuredValue ?? string.Empty).Trim().TrimEnd('/');
        if (configured.Length > 0 && Uri.TryCreate(configured, UriKind.Absolute, out var absolute))
        {
            return absolute.GetLeftPart(UriPartial.Authority);
        }

        return $"{request.Scheme}://{request.Host}";
    }
}
