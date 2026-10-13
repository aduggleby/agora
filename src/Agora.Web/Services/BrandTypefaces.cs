using SkiaSharp;
using IOPath = System.IO.Path;

namespace Agora.Web.Services;

/// <summary>
/// The DM Sans typefaces used by generated images, loaded from the app's <c>Fonts</c> directory. The Linux SkiaSharp
/// build in use has no fontconfig, so system font lookup returns an empty typeface that renders nothing; every text
/// drawn by the app must come from these files. <see cref="SKTypeface"/> is immutable and safe to share.
/// </summary>
public sealed class BrandTypefaces
{
    public static string DefaultDirectory => IOPath.Combine(AppContext.BaseDirectory, "Fonts");

    public SKTypeface Regular { get; }
    public SKTypeface Medium { get; }
    public SKTypeface Bold { get; }

    public BrandTypefaces(string fontsDirectory)
    {
        Regular = Load(IOPath.Combine(fontsDirectory, "DMSans-Regular.ttf"));
        Medium = Load(IOPath.Combine(fontsDirectory, "DMSans-Medium.ttf"));
        Bold = Load(IOPath.Combine(fontsDirectory, "DMSans-Bold.ttf"));
    }

    private static SKTypeface Load(string path) =>
        SKTypeface.FromFile(path) ?? throw new FileNotFoundException($"Font file is missing or not a readable TTF: {path}", path);
}
