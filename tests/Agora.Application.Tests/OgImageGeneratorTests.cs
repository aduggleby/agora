using Agora.Web.Services;
using SkiaSharp;

namespace Agora.Application.Tests;

/// <summary>
/// Runtime smoke of the link-preview (OG) image drawing, plus the background budget: backgrounds are decoded with the
/// restricted format set, extreme aspect ratios are skipped, accepted ones are cropped to the canvas in one step, and
/// the decode runs inside the shared raster decode slots under the time budget.
/// </summary>
[Collection(RasterDecodeSlotsCollection.Name)]
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

    [Fact]
    public async Task Background_waits_for_a_raster_slot_and_falls_back_uncached_on_timeout_without_decoding()
    {
        var generator = new OgImageGenerator(FontsDirectory, decodeTimeoutSeconds: 1);
        var withoutBackground = await RenderAsync(generator, null);
        var slots = SharePreviewImageGenerator.RasterDecodeSlots;
        // A large header within the budget: decoding it would allocate width x height x 4 bytes.
        var background = new TrackingStream(PngCrafting.HeaderOnly(4000, 4000));

        // Hold both slots as two abandoned decodes would.
        await slots.WaitAsync();
        await slots.WaitAsync();
        OgImageGenerator.OgImage result;
        long started;
        try
        {
            started = SharePreviewImageGenerator.RasterDecodesStarted;

            result = await generator.GenerateShareOgImageAsync(background, null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false);

            Assert.Equal(started, SharePreviewImageGenerator.RasterDecodesStarted);
            Assert.Equal(0, slots.CurrentCount);
        }
        finally
        {
            slots.Release(2);
        }

        Assert.False(result.Cacheable);
        Assert.Equal(withoutBackground, result.Png);
        Assert.Equal(0, background.BytesRead);
        Assert.True(background.Disposed);

        // With the slots free again, a background is decoded and drawn and the result is cacheable.
        var retried = await generator.GenerateShareOgImageAsync(
            new MemoryStream(ImageCrafting.Solid(64, 48, Navy)), null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false);
        Assert.True(retried.Cacheable);
        Assert.NotEqual(withoutBackground, retried.Png);
    }

    [Fact]
    public async Task Rendered_backgrounds_and_skipped_ones_are_cacheable()
    {
        var generator = new OgImageGenerator(FontsDirectory);

        var drawn = await generator.GenerateShareOgImageAsync(await PngAsync(64, 48), null, "t", null, "a.zip", 1, "1 KB", isExpired: false);
        var skipped = await generator.GenerateShareOgImageAsync(new MemoryStream("not an image"u8.ToArray()), null, "t", null, "a.zip", 1, "1 KB", isExpired: false);

        Assert.True(drawn.Cacheable);
        Assert.True(skipped.Cacheable);
    }

    [Fact]
    public void Upload_check_accepts_a_4k_background_and_refuses_oversized_or_undecodable_ones()
    {
        Assert.True(OgImageGenerator.IsAcceptableBackground(new MemoryStream(ImageCrafting.Solid(3840, 2160, Navy))));

        Assert.False(OgImageGenerator.IsAcceptableBackground(new MemoryStream(PngCrafting.HeaderOnly(4001, 4000))));
        var overBudget = Assert.Throws<PreviewSourceRejectedException>(() =>
            UntrustedImageDecoding.OpenHeader(new MemoryStream(PngCrafting.HeaderOnly(4001, 4000)), OgImageGenerator.MaxBackgroundPixels));
        Assert.Contains("pixel budget", overBudget.Message);
        Assert.False(OgImageGenerator.IsAcceptableBackground(new MemoryStream(PngCrafting.DoubleIhdr(12_000, 12_000, 1, 1))));
        Assert.False(OgImageGenerator.IsAcceptableBackground(new MemoryStream(ImageCrafting.Gif(8, 8))));
        Assert.False(OgImageGenerator.IsAcceptableBackground(new MemoryStream("not an image"u8.ToArray())));

        var path = Path.Combine(Path.GetTempPath(), $"agora-og-background-{Guid.NewGuid():N}.png");
        try
        {
            File.WriteAllBytes(path, PngCrafting.HeaderOnly(5000, 5000));
            Assert.False(OgImageGenerator.IsAcceptableBackground(path));
            File.WriteAllBytes(path, ImageCrafting.Solid(64, 48, Navy));
            Assert.True(OgImageGenerator.IsAcceptableBackground(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Stored_background_over_the_pixel_budget_falls_back_to_the_gradient_and_is_cacheable()
    {
        var generator = new OgImageGenerator(FontsDirectory);
        var withoutBackground = await RenderAsync(generator, null);

        var legacy = await generator.GenerateShareOgImageAsync(
            new MemoryStream(PngCrafting.HeaderOnly(5000, 5000)), null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false);

        Assert.True(legacy.Cacheable);
        Assert.Equal(withoutBackground, legacy.Png);
    }

    private static async Task<byte[]> RenderAsync(OgImageGenerator generator, Stream? background) =>
        (await generator.GenerateShareOgImageAsync(background, null, "Quarterly report", "From Alex", "report.pdf", 3, "12.4 MB", isExpired: false)).Png;

    private sealed class TrackingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public long BytesRead { get; private set; }
        public bool Disposed { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = base.Read(buffer, offset, count);
            BytesRead += read;
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = base.Read(buffer);
            BytesRead += read;
            return read;
        }

        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private static SKColor CornerPixel(byte[] png)
    {
        Assert.Equal((1200, 630), ImageCrafting.Dimensions(png));
        return ImageCrafting.Pixel(png, 20, 20);
    }

    private static Task<MemoryStream> PngAsync(int width, int height) =>
        Task.FromResult(new MemoryStream(ImageCrafting.Solid(width, height, Navy)));
}
