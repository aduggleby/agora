using Microsoft.Extensions.Configuration;

namespace Agora.Infrastructure.Logging;

/// <summary>
/// Daily rolling log file settings (<c>Agora:Logging:File:*</c>). The console sink is always on.
/// <see cref="RetainedDays"/> null means unlimited (only reachable through the legacy Serilog setting).
/// </summary>
public sealed record LogFileOptions(bool Enabled, string Path, int? RetainedDays)
{
    public const string Section = "Agora:Logging:File";
    public const string FileNamePattern = "agora-.log";
    public const int DefaultRetainedDays = 30;

    /// <summary>Legacy file path setting (before 0.9.18); still honoured so existing installs keep logging to the same place.</summary>
    public const string LegacySerilogPathKey = "Serilog:WriteTo:0:Args:path";

    /// <summary>Legacy retention setting (before 0.9.18); still honoured so existing installs keep their log history.</summary>
    public const string LegacySerilogRetentionKey = "Serilog:WriteTo:0:Args:retainedFileCountLimit";

    /// <summary>
    /// Resolves the settings. Path precedence: the legacy <c>Serilog:WriteTo:0:Args:path</c> directory (existing installs),
    /// then <c>Agora:Logging:File:Path</c>, then <c>logs</c>. RetainedDays uses the same precedence: a present legacy
    /// <c>retainedFileCountLimit</c> is honoured as Serilog would (empty/null = unlimited, numbers with a minimum of 1),
    /// then <c>Agora:Logging:File:RetainedDays</c> (clamped to 1-3650), then 30.
    /// </summary>
    public static LogFileOptions Resolve(IConfiguration configuration)
    {
        var legacyFile = configuration[LegacySerilogPathKey];
        var legacyDirectory = string.IsNullOrWhiteSpace(legacyFile) ? null : System.IO.Path.GetDirectoryName(legacyFile.Trim());
        var configuredPath = configuration[$"{Section}:Path"];
        var path = !string.IsNullOrWhiteSpace(legacyDirectory) ? legacyDirectory
            : !string.IsNullOrWhiteSpace(configuredPath) ? configuredPath.Trim()
            : "logs";

        return new LogFileOptions(
            !bool.TryParse(configuration[$"{Section}:Enabled"], out var enabled) || enabled,
            path,
            ResolveRetainedDays(configuration));
    }

    private static int? ResolveRetainedDays(IConfiguration configuration)
    {
        if (TryGetLegacyRetention(configuration, out var legacy))
        {
            if (string.IsNullOrWhiteSpace(legacy))
            {
                return null;
            }

            if (int.TryParse(legacy, out var legacyDays))
            {
                return Math.Max(1, legacyDays);
            }
        }

        return Math.Clamp(int.TryParse(configuration[$"{Section}:RetainedDays"], out var days) ? days : DefaultRetainedDays, 1, 3650);
    }

    private static bool TryGetLegacyRetention(IConfiguration configuration, out string? value)
    {
        // A key that is present with a null value (JSON null) reads as null like a missing key; ask the providers.
        value = configuration[LegacySerilogRetentionKey];
        return value is not null ||
               (configuration is IConfigurationRoot root && root.Providers.Any(p => p.TryGet(LegacySerilogRetentionKey, out _)));
    }
}
