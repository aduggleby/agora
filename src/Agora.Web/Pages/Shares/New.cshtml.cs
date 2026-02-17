using System.Security.Claims;
using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Shares;

[Authorize]
public class NewModel(AuthService authService, ShareManager manager, IOptions<AgoraOptions> options) : PageModel
{
    public string DraftShareId { get; private set; } = string.Empty;
    public ShareManager.DraftTemplateState DraftTemplate { get; private set; } = new("", "account_default", "", "", "", null, null, null, "center");
    public IReadOnlyList<ShareManager.StagedUploadFile> StagedUploads { get; private set; } = [];
    public string TemplateModeForDraft { get; private set; } = "account_default";
    public string AccountDefaultNotifyModeLabel { get; private set; } = "First download only";
    public string AccountDefaultExpiryModeLabel { get; private set; } = "7 days";
    public string AccountDefaultExpiryMode { get; private set; } = "7_days";
    public string ShareToken { get; private set; } = string.Empty;
    public string SuggestedShareToken { get; private set; } = string.Empty;
    public string ShareLinkPrefix { get; private set; } = string.Empty;

    public async Task OnGet(CancellationToken ct)
    {
        var email = User.FindFirstValue(ClaimTypes.Email) ?? string.Empty;
        var requestedDraftShareId = Request.Query["draftShareId"].ToString();
        try
        {
            DraftShareId = await manager.EnsureDraftShareAsync(email, requestedDraftShareId, ct);
        }
        catch
        {
            DraftShareId = await manager.EnsureDraftShareAsync(email, null, ct);
        }

        DraftTemplate = await manager.GetDraftTemplateAsync(email, DraftShareId, ct);
        StagedUploads = await manager.ListStagedUploadsForDraftAsync(email, DraftShareId, ct);
        TemplateModeForDraft = string.Equals(DraftTemplate.TemplateMode, "per_upload", StringComparison.OrdinalIgnoreCase)
            ? "per_upload"
            : "account_default";

        var notifyMode = await authService.GetDefaultNotifyModeAsync(email, ct);
        AccountDefaultNotifyModeLabel = notifyMode switch
        {
            "none" => "None",
            "every_time" => "Every download",
            _ => "First download only"
        };

        AccountDefaultExpiryMode = await authService.GetDefaultExpiryModeAsync(email, ct);
        AccountDefaultExpiryModeLabel = AccountDefaultExpiryMode switch
        {
            "1_hour" => "1 hour",
            "24_hours" => "24 hours",
            "30_days" => "30 days",
            "1_year" => "1 year",
            "indefinite" => "Indefinite",
            _ => "7 days"
        };

        var requestedShareToken = Request.Query["shareToken"].ToString().Trim();
        ShareToken = IsValidShareToken(requestedShareToken)
            ? requestedShareToken
            : await manager.GenerateUniqueShareTokenAsync(8, ct);
        ShareLinkPrefix = $"{ResolvePublicBaseUrl(options.Value.PublicBaseUrl, Request)}/s/";

        var suggestedShareToken = Request.Query["suggestedShareToken"].ToString().Trim();
        SuggestedShareToken = IsValidShareToken(suggestedShareToken)
            ? suggestedShareToken
            : string.Empty;

        ViewData["Title"] = "Share files";
        ViewData["Message"] = Request.Query["msg"].ToString();
    }

    private static bool IsValidShareToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 3 || value.Length > 64)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!char.IsLetterOrDigit(ch) && ch is not '-' and not '_')
            {
                return false;
            }
        }

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
