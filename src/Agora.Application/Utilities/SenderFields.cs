using System.Net.Mail;
using System.Text;

namespace Agora.Application.Utilities;

/// <summary>Cleaning and validation of the sender fields a public uploader types (name, email).</summary>
public static class SenderFields
{
    /// <summary>Strips control characters and collapses whitespace runs; sender text ends up in page markup and mail.</summary>
    public static string NormalizeText(string? raw)
    {
        var text = raw ?? string.Empty;
        var builder = new StringBuilder(text.Length);
        var pendingSpace = false;
        foreach (var ch in text)
        {
            if (char.IsWhiteSpace(ch))
            {
                pendingSpace = builder.Length > 0;
                continue;
            }

            if (char.IsControl(ch))
            {
                continue;
            }

            if (pendingSpace)
            {
                builder.Append(' ');
                pendingSpace = false;
            }

            builder.Append(ch);
        }

        return builder.ToString();
    }

    /// <summary>True when the value is a bare address (no display name, no extra text) that the mail parser accepts.</summary>
    public static bool IsValidEmailAddress(string? value)
    {
        try
        {
            var normalized = (value ?? string.Empty).Trim();
            var parsed = new MailAddress(normalized);
            return string.Equals(parsed.Address, normalized, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
