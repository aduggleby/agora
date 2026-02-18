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

    public static string Sanitize(string value)
    {
        var fileName = Path.GetFileName(value).Trim();
        fileName = Regex.Replace(fileName, "[\\x00-\\x1F\\x7F]+", string.Empty);
        fileName = fileName.TrimEnd('.', ' ');
        return string.IsNullOrWhiteSpace(fileName) ? "archive" : fileName;
    }
}
