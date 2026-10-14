using System.Reflection;

namespace Agora.Web.Startup;

/// <summary>The application version shown in the footer: the informational version without the build metadata suffix.</summary>
public static class AppVersion
{
    public static readonly string Current = Resolve();

    private static string Resolve()
    {
        var assembly = typeof(AppVersion).Assembly;
        var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        var version = string.IsNullOrWhiteSpace(informational) ? assembly.GetName().Version?.ToString(3) : informational;
        if (string.IsNullOrWhiteSpace(version))
        {
            return "dev";
        }

        var plus = version.IndexOf('+');
        return plus > 0 ? version[..plus] : version;
    }
}
