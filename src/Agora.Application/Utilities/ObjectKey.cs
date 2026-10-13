using System.Text.RegularExpressions;

namespace Agora.Application.Utilities;

/// <summary>
/// Single place that validates object-store keys and prefixes. Keys are relative paths with forward slashes and no
/// empty, "." or ".." segments; rooted input (leading '/' or '\', drive letters) is rejected before any rewriting.
/// </summary>
public static partial class ObjectKey
{
    public static string Normalize(string? key)
    {
        if (!TryNormalize(key, out var normalized))
        {
            throw new ArgumentException($"Invalid object key '{key}'.", nameof(key));
        }

        return normalized;
    }

    public static bool TryNormalize(string? key, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(key) || key[0] is '/' or '\\' || DriveRoot().IsMatch(key))
        {
            return false;
        }

        var candidate = key.Replace('\\', '/');
        if (candidate.Split('/').Any(segment => segment is "" or "." or ".." || segment.Trim().Length == 0 || segment.Any(char.IsControl)))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    /// <summary>Validates a delete prefix: at least two segments and a trailing '/'. Returns it normalized.</summary>
    public static string NormalizePrefix(string? prefix)
    {
        var trimmed = prefix ?? string.Empty;
        if (!trimmed.EndsWith('/') && !trimmed.EndsWith('\\'))
        {
            throw new ArgumentException($"Object prefix '{prefix}' must end with '/'.", nameof(prefix));
        }

        var key = Normalize(trimmed[..^1]);
        if (key.Split('/').Length < 2)
        {
            throw new ArgumentException($"Object prefix '{prefix}' must have at least two segments.", nameof(prefix));
        }

        return key + "/";
    }

    /// <summary>Resolves an <c>internal:relative/path</c> background marker to a key, or null.</summary>
    public static string? FromInternalMarker(string? marker)
    {
        const string scheme = "internal:";
        if (marker is null || !marker.StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return TryNormalize(marker[scheme.Length..].TrimStart('/', '\\'), out var key) ? key : null;
    }

    [GeneratedRegex(@"^[A-Za-z]:")]
    private static partial Regex DriveRoot();
}
