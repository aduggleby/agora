using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Agora.Web.Pages.Auth;

/// <summary>
/// Base for the pages behind emailed confirmation links. GET only renders a confirm button, so link scanners
/// and mail-client prefetches never consume the single-use token; the CSRF-protected POST performs the action.
/// Concrete pages carry the per-IP "AuthEndpoints" rate limit like the other auth handlers.
/// </summary>
public abstract class ConfirmActionPageModel : PageModel
{
    public string Email { get; private set; } = string.Empty;
    public string Token { get; private set; } = string.Empty;
    public bool CanSubmit { get; private set; }
    /// <summary>Shown above the form when the POST re-renders it (for example a wrong password).</summary>
    public string? Error { get; private set; }

    /// <summary>True when the form asks for the account password (posted as <c>password</c>).</summary>
    public virtual bool RequiresPassword => false;

    /// <summary>The page's own path, without the query string: tokens travel only in the hidden form fields.</summary>
    public string FormAction => Request.Path.Value ?? "/";

    public abstract string Heading { get; }
    public abstract string Description { get; }
    public abstract string ButtonLabel { get; }

    public IActionResult OnGet()
    {
        // The token is in this page's URL: never send it along as a Referer.
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Email = Request.Query["email"].ToString().Trim();
        Token = Request.Query["token"].ToString().Trim();
        CanSubmit = !string.IsNullOrWhiteSpace(Email) && !string.IsNullOrWhiteSpace(Token);
        ViewData["Title"] = Heading;
        return Page();
    }

    public Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        Response.Headers["Referrer-Policy"] = "no-referrer";
        var email = Request.Form["email"].ToString().Trim();
        var token = Request.Form["token"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(token))
        {
            return Task.FromResult<IActionResult>(Redirect("/login?msg=Confirmation%20link%20is%20invalid"));
        }

        return ConfirmAsync(email, token, ct);
    }

    protected abstract Task<IActionResult> ConfirmAsync(string email, string token, CancellationToken ct);

    /// <summary>Renders the form again for the same link, with an error; the token was not used.</summary>
    protected IActionResult ShowFormWithError(string email, string token, string error)
    {
        Email = email;
        Token = token;
        CanSubmit = true;
        Error = error;
        ViewData["Title"] = Heading;
        return Page();
    }
}
