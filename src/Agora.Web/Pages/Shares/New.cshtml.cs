using System.Security.Claims;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Agora.Web.Auth;
using Agora.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Shares;

[Authorize]
public class NewModel(AuthService authService, ShareManager manager, IOptions<AgoraOptions> options, PublicBaseUrlResolver publicBaseUrls) : PageModel
{
    private readonly AgoraOptions _options = options.Value;

    /// <summary>A staged file as the page renders it; <see cref="DirectLinkEligible"/> mirrors the stage response flag.</summary>
    public sealed record StagedUploadRow(string UploadId, string OriginalFileName, long OriginalSizeBytes, bool DirectLinkEligible);

    public string DraftShareId { get; private set; } = string.Empty;
    public ShareManager.DraftTemplateState DraftTemplate { get; private set; } = new("", "account_default", "", "", "", null, null, null, "center");
    public IReadOnlyList<StagedUploadRow> StagedUploads { get; private set; } = [];
    public IReadOnlyList<DirectLinkDuration> DirectLinkDurationOptions => DirectLinkDurations.All;
    public string DefaultDirectLinkDuration => DirectLinkDurations.DefaultWireValue;
    public string TemplateModeForDraft { get; private set; } = "account_default";
    public string AccountDefaultNotifyModeLabel { get; private set; } = "First download only";
    public string AccountDefaultExpiryModeLabel { get; private set; } = "7 days";
    public string AccountDefaultExpiryMode { get; private set; } = "7_days";
    public string ShareToken { get; private set; } = string.Empty;
    public string ShareLinkPrefix { get; private set; } = string.Empty;
    public long MaxFileSizeBytes => _options.MaxFileSizeBytes;
    public long MaxTotalUploadBytes => _options.MaxTotalUploadBytes;
    public int MaxFilesPerShare => _options.MaxFilesPerShare;

    public async Task<IActionResult> OnGet(CancellationToken ct)
    {
        if (User.UserId() is not { } userId)
        {
            return Redirect("/login");
        }

        var requestedDraftShareId = Request.Query["draftShareId"].ToString();
        try
        {
            DraftShareId = await manager.EnsureDraftShareAsync(userId, requestedDraftShareId, ct);
        }
        catch
        {
            DraftShareId = await manager.EnsureDraftShareAsync(userId, null, ct);
        }

        DraftTemplate = await manager.GetDraftTemplateAsync(userId, DraftShareId, ct);
        StagedUploads = (await manager.ListStagedUploadsForDraftAsync(userId, DraftShareId, ct))
            .Select(x => new StagedUploadRow(x.UploadId, x.OriginalFileName, x.OriginalSizeBytes, ContentTypePolicy.Resolve(x.OriginalFileName).Inline))
            .ToList();
        TemplateModeForDraft = string.Equals(DraftTemplate.TemplateMode, "per_upload", StringComparison.OrdinalIgnoreCase)
            ? "per_upload"
            : "account_default";

        var notifyMode = await authService.GetDefaultNotifyModeAsync(userId, ct);
        AccountDefaultNotifyModeLabel = notifyMode switch
        {
            "none" => "None",
            "every_time" => "Every download",
            _ => "First download only"
        };

        AccountDefaultExpiryMode = await authService.GetDefaultExpiryModeAsync(userId, ct);
        AccountDefaultExpiryModeLabel = AccountDefaultExpiryMode switch
        {
            "1_hour" => "1 hour",
            "24_hours" => "24 hours",
            "30_days" => "30 days",
            "1_year" => "1 year",
            "indefinite" => "Indefinite",
            _ => "7 days"
        };

        // Never prefilled from the query: a crafted link could otherwise choose the public link of a share
        // the owner is about to create. The token is generated here or typed by the owner on the page.
        ShareToken = await manager.GenerateUniqueShareTokenAsync(8, ct);
        ShareLinkPrefix = $"{publicBaseUrls.Resolve(Request)}/s/";

        ViewData["Title"] = "Share files";
        ViewData["Message"] = Request.Query["msg"].ToString();
        return Page();
    }

    public static string DirectLinkDurationLabel(DirectLinkDuration duration) => duration switch
    {
        DirectLinkDuration.ThirtyMinutes => "30 min",
        DirectLinkDuration.SixHours => "6 hours",
        DirectLinkDuration.SevenDays => "7 days",
        _ => "1 day"
    };
}
