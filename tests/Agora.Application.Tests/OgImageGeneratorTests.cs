using Agora.Web.Services;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

namespace Agora.Application.Tests;

/// <summary>
/// Runtime smoke of the link-preview (OG) image drawing, plus the background budget: backgrounds are decoded with the
/// restricted decoder set, extreme aspect ratios are skipped, and accepted ones are cropped to the canvas in one step.
/// </summary>
public sealed class OgImageGeneratorTests
{
    private static readonly string FontsDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Fonts"));
    private static readonly Rgba32 Navy = new(30, 60, 90);

    [Fact]
    public async Task Default_og_image_renders()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var png = await generator.GenerateDefaultOgImageAsync("Agora", "Self hosted secure file transfer");

        using var image = Image.Load<Rgba32>(png);
        Assert.Equal(1200, image.Width);
        Assert.Equal(630, image.Height);
    }

    [Fact]
    public async Task Share_og_image_background_is_decoded_and_drawn()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var withoutBackground = await RenderAsync(generator, null);
        var withBackground = await RenderAsync(generator, await PngAsync(64, 48));

        // (20, 20) lies outside the card: cream gradient without a background, blurred navy under a dark overlay with one.
        var plain = CornerPixel(withoutBackground);
        var dark = CornerPixel(withBackground);
        Assert.True(plain.R > 200, $"expected cream corner, got {plain}");
        Assert.True(dark.R < 100 && dark.B > dark.R, $"expected darkened navy corner, got {dark}");
    }

    [Theory]
    [InlineData(400, 1)]
    [InlineData(1, 400)]
    public async Task Extreme_aspect_backgrounds_are_skipped_without_error(int width, int height)
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var withoutBackground = await RenderAsync(generator, null);
        var skipped = await RenderAsync(generator, await PngAsync(width, height));

        // Skipped at Identify time: the output is byte-identical to rendering with no background at all.
        Assert.Equal(withoutBackground, skipped);
    }

    [Fact]
    public async Task Double_ihdr_png_background_is_skipped_before_decoding()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var withoutBackground = await RenderAsync(generator, null);
        var skipped = await RenderAsync(generator, new MemoryStream(PngCrafting.DoubleIhdr(12_000, 12_000, 1, 1)));

        Assert.Equal(withoutBackground, skipped);
    }

    [Fact]
    public async Task Wide_background_at_the_aspect_limit_is_cropped_to_the_canvas()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        // 10:1 is the limit: this goes through the single ResizeMode.Crop operation (no cover-sized intermediate).
        var png = await RenderAsync(generator, await PngAsync(4000, 400));

        using var image = Image.Load<Rgba32>(png);
        Assert.Equal(1200, image.Width);
        Assert.Equal(630, image.Height);
        var corner = CornerPixel(png);
        Assert.True(corner.R < 100 && corner.B > corner.R, $"expected darkened navy corner, got {corner}");
    }

    private static Task<byte[]> RenderAsync(OgImageGenerator generator, Stream? background) =>
        generator.GenerateShareOgImageAsync(background, null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false);

    private static Rgba32 CornerPixel(byte[] png)
    {
        using var image = Image.Load<Rgba32>(png);
        Assert.Equal(1200, image.Width);
        Assert.Equal(630, image.Height);
        return image[20, 20];
    }

    private static async Task<MemoryStream> PngAsync(int width, int height)
    {
        using var source = new Image<Rgba32>(width, height, Navy);
        var output = new MemoryStream();
        await source.SaveAsPngAsync(output);
        output.Position = 0;
        return output;
    }
}
