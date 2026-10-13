using System.Text;

namespace Agora.Application.Utilities;

/// <summary>
/// Display names that end up in the <c>From</c> header of outgoing mail. Part of the name may come from an anonymous
/// uploader (the "on behalf of" sender), so it is reduced to printable text without header or address delimiters
/// before it is quoted.
/// </summary>
public static class EmailDisplayName
{
    public const int MaxLength = 80;

    /// <summary>
    /// Removes control characters, quotes, backslashes, angle brackets, commas, colons and semicolons, collapses
    /// whitespace and caps the result at <paramref name="maxLength"/> characters (never splitting a surrogate pair).
    /// Returns an empty string when nothing printable remains.
    /// </summary>
    public static string Sanitize(string? value, int maxLength = MaxLength)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(Math.Min(value.Length, maxLength));
        var pendingSpace = false;
        foreach (var ch in value)
        {
            if (char.IsWhiteSpace(ch))
            {
                pendingSpace = builder.Length > 0;
                continue;
            }

            if (char.IsControl(ch) || ch is '"' or '\\' or '<' or '>' or ',' or ':' or ';')
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

        if (builder.Length <= maxLength)
        {
            return builder.ToString();
        }

        var cut = maxLength;
        if (char.IsHighSurrogate(builder[cut - 1]))
        {
            cut--;
        }

        return builder.ToString(0, cut).TrimEnd();
    }

    /// <summary>
    /// The <c>From</c> value: <c>"Display Name" &lt;address&gt;</c>, or the bare address without a display name.
    /// The name is quoted with <c>"</c> and <c>\</c> escaped; carriage returns and line feeds in either part are
    /// rejected rather than escaped.
    /// </summary>
    public static string BuildFromHeader(string address, string? displayName)
    {
        var normalizedAddress = (address ?? string.Empty).Trim();
        if (normalizedAddress.Length == 0)
        {
            throw new ArgumentException("A from address is required.", nameof(address));
        }

        if (normalizedAddress.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch) || ch is '<' or '>' or '"' or ','))
        {
            throw new ArgumentException("The from address contains characters that are not allowed.", nameof(address));
        }

        var name = (displayName ?? string.Empty).Trim();
        if (name.Length == 0)
        {
            return normalizedAddress;
        }

        if (name.Any(ch => ch is '\r' or '\n'))
        {
            throw new ArgumentException("The display name must not contain line breaks.", nameof(displayName));
        }

        var quoted = new StringBuilder(name.Length + 2);
        quoted.Append('"');
        foreach (var ch in name)
        {
            if (ch is '"' or '\\')
            {
                quoted.Append('\\');
            }

            quoted.Append(ch);
        }

        quoted.Append('"');
        return $"{quoted} <{normalizedAddress}>";
    }
}
