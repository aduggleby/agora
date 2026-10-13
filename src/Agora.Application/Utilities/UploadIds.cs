namespace Agora.Application.Utilities;

/// <summary>
/// Staged-upload ids are server-generated GUIDs ("N" format). User-supplied ids are
/// accepted only in the "N" or "D" GUID formats and normalised to lowercase "N" before
/// they are allowed anywhere near a filesystem path.
/// </summary>
public static class UploadIds
{
    public static bool TryNormalize(string? rawId, out string normalizedId)
    {
        normalizedId = string.Empty;
        var trimmed = rawId?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > 36 || !trimmed.All(IsAsciiHexOrDash))
        {
            return false;
        }

        if (Guid.TryParseExact(trimmed, "N", out var guid) || Guid.TryParseExact(trimmed, "D", out guid))
        {
            normalizedId = guid.ToString("N");
            return true;
        }

        return false;
    }

    private static bool IsAsciiHexOrDash(char c) => char.IsAsciiHexDigit(c) || c == '-';
}
