using System.Text.RegularExpressions;

namespace Agora.Application.Utilities;

public static class ArchiveNameResolver
{
    public static string Resolve(string? preferredName, IReadOnlyList<string> originalFilenames, DateTime utcNow)
    {
        if (!string.IsNullOrWhiteSpace(preferredName))
        {
            return EnsureZipExtension(Sanitize(preferredName));
        }

        if (originalFilenames.Count == 1)
        {
            var baseName = Path.GetFileNameWithoutExtension(originalFilenames[0]);
            return EnsureZipExtension(Sanitize(baseName));
        }

        return $"files-{utcNow:yyyyMMdd-HHmmss}.zip";
    }

    private static string EnsureZipExtension(string value)
    {
        return value.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ? value : $"{value}.zip";
    }

    /// <summary>
    /// Reduces an untrusted name to a single path segment: backslashes count as separators on
    /// every platform, directory parts (including leading slashes and ".." segments) are dropped,
    /// and control characters are removed.
    /// </summary>
    public static string Sanitize(string value)
    {
        var normalized = (value ?? string.Empty).Replace('\\', '/');
        var fileName = normalized[(normalized.LastIndexOf('/') + 1)..].Trim();
        fileName = Regex.Replace(fileName, "[\\x00-\\x1F\\x7F]+", string.Empty);
        // A colon would be a drive or alternate-data-stream separator for Windows extractors.
        fileName = fileName.Replace(':', '_');
        fileName = fileName.TrimEnd('.', ' ');
        if (string.IsNullOrWhiteSpace(fileName) || fileName.All(c => c == '.'))
        {
            return "archive";
        }

        return fileName;
    }

    /// <summary>
    /// Makes <paramref name="name"/> unique among <paramref name="taken"/> (case-insensitive, since
    /// common extractors treat entry names that way) by appending " (2)", " (3)", ... before the
    /// extension, and records the chosen name in <paramref name="taken"/>.
    /// </summary>
    public static string Deduplicate(string name, ISet<string> taken)
    {
        if (taken.Add(name))
        {
            return name;
        }

        var extension = Path.GetExtension(name);
        var stem = name[..^extension.Length];
        for (var i = 2; ; i++)
        {
            var candidate = $"{stem} ({i}){extension}";
            if (taken.Add(candidate))
            {
                return candidate;
            }
        }
    }
}
