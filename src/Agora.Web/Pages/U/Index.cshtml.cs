using Agora.Application.Models;
using Agora.Infrastructure.Auth;
using Agora.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Agora.Web.Pages.U;

public class IndexModel(AuthService authService, ShareManager manager, IOptions<AgoraOptions> options) : PageModel
{
    private readonly AgoraOptions _options = options.Value;

    public bool IsInvalidToken { get; private set; }
    public bool IsSubmissionSuccess { get; private set; }
    public string UploadToken { get; private set; } = string.Empty;
    public string DraftShareId { get; private set; } = string.Empty;
    public string RecipientDisplayName { get; private set; } = string.Empty;
    public long MaxFileSizeBytes => _options.MaxFileSizeBytes;
    public long MaxTotalUploadBytes => _options.MaxTotalUploadBytes;
    public int MaxFilesPerShare => _options.MaxFilesPerShare;

    public async Task<IActionResult> OnGet(string token, CancellationToken ct)
    {
        var uploadToken = (token ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(uploadToken))
        {
            IsInvalidToken = true;
            ViewData["Title"] = "Upload link";
            return Page();
        }

        var user = await authService.FindByUploadTokenAsync(uploadToken, ct);
        if (user is null)
        {
            IsInvalidToken = true;
            ViewData["Title"] = "Upload link";
            return Page();
        }

        UploadToken = uploadToken;
        RecipientDisplayName = string.IsNullOrWhiteSpace(user.DisplayName)
            ? "this recipient"
            : user.DisplayName.Trim();
        var submitted = Request.Query["submitted"].ToString().Trim();
        var legacyMessage = Request.Query["msg"].ToString().Trim();
        IsSubmissionSuccess = string.Equals(submitted, "1", StringComparison.Ordinal) ||
                              string.Equals(legacyMessage, "Thanks, your files are being processed.", StringComparison.Ordinal);

        if (!IsSubmissionSuccess)
        {
            DraftShareId = await manager.EnsureDraftShareAsync(user.Email, null, ct);
        }

        ViewData["Title"] = IsSubmissionSuccess ? "Upload scheduled" : "Send files";
        return Page();
    }
}
