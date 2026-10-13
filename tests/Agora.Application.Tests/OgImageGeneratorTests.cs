using Agora.Web.Services;
using SkiaSharp;

namespace Agora.Application.Tests;

/// <summary>
/// Runtime smoke of the link-preview (OG) image drawing, plus the background budget: backgrounds are decoded with the
/// restricted format set, extreme aspect ratios are skipped, and accepted ones are cropped to the canvas in one step.
/// </summary>
public sealed class OgImageGeneratorTests
{
    private static readonly string FontsDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Fonts"));
    private static readonly SKColor Navy = new(30, 60, 90);

    [Fact]
    public async Task Default_og_image_renders()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var png = await generator.GenerateDefaultOgImageAsync("Agora", "Self hosted secure file transfer");

        Assert.Equal((1200, 630), ImageCrafting.Dimensions(png));
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
        Assert.True(plain.Red > 200, $"expected cream corner, got {plain}");
        Assert.True(dark.Red < 100 && dark.Blue > dark.Red, $"expected darkened navy corner, got {dark}");
    }

    [Theory]
    [InlineData(400, 1)]
    [InlineData(1, 400)]
    public async Task Extreme_aspect_backgrounds_are_skipped_without_error(int width, int height)
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var withoutBackground = await RenderAsync(generator, null);
        var skipped = await RenderAsync(generator, await PngAsync(width, height));

        // Skipped from the header: the output is byte-identical to rendering with no background at all.
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

        // 10:1 is the limit: this goes through the single cover-crop draw (no cover-sized intermediate).
        var png = await RenderAsync(generator, await PngAsync(4000, 400));

        Assert.Equal((1200, 630), ImageCrafting.Dimensions(png));
        var corner = CornerPixel(png);
        Assert.True(corner.Red < 100 && corner.Blue > corner.Red, $"expected darkened navy corner, got {corner}");
    }

    [Fact]
    public async Task Animated_webp_background_shows_the_first_frame()
    {
        var generator = new OgImageGenerator(FontsDirectory);
        var webp = ImageCrafting.AnimatedWebp(64, 48, new SKColor(220, 30, 30), new SKColor(30, 30, 220));

        var png = await RenderAsync(generator, new MemoryStream(webp));

        // Blurred red under the dark overlay: still clearly red rather than the blue second frame.
        var corner = CornerPixel(png);
        Assert.True(corner.Red > 60 && corner.Red > corner.Blue * 2, $"expected darkened red corner, got {corner}");
    }

    private static Task<byte[]> RenderAsync(OgImageGenerator generator, Stream? background) =>
        generator.GenerateShareOgImageAsync(background, null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false);

    private static SKColor CornerPixel(byte[] png)
    {
        Assert.Equal((1200, 630), ImageCrafting.Dimensions(png));
        return ImageCrafting.Pixel(png, 20, 20);
    }

    private static Task<MemoryStream> PngAsync(int width, int height) =>
        Task.FromResult(new MemoryStream(ImageCrafting.Solid(width, height, Navy)));
}
