using Agora.Web.Services;
using SkiaSharp;

namespace Agora.Application.Tests;

/// <summary>
/// The decode rules shared by previews and link-preview backgrounds: format and pixel budget are decided from the
/// header, and formats that support it are downscaled during decoding instead of being materialised at full size.
/// </summary>
public sealed class UntrustedImageDecodingTests
{
    [Theory]
    [InlineData(SKEncodedImageFormat.Jpeg)]
    [InlineData(SKEncodedImageFormat.Webp)]
    public void Large_scalable_sources_are_downscaled_during_decoding(SKEncodedImageFormat format)
    {
        var source = ImageCrafting.Solid(4000, 3000, new SKColor(10, 120, 200), format);

        using var codec = UntrustedImageDecoding.OpenHeader(new MemoryStream(source), maxPixels: 50_000_000);
        using var bitmap = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(400, 300));

        // Never below the box (so the final draw does not upscale) and far below the source (JPEG scales in 1/8 steps).
        Assert.True(bitmap.Width >= 400 && bitmap.Height >= 300, $"decoded {bitmap.Width}x{bitmap.Height}");
        Assert.True(bitmap.Width <= 1000 && bitmap.Height <= 750, $"decoded {bitmap.Width}x{bitmap.Height}");
        Assert.Equal(SKColorType.Rgba8888, bitmap.ColorType);
        var pixel = bitmap.GetPixel(bitmap.Width / 2, bitmap.Height / 2);
        Assert.True(pixel.Blue > 150 && pixel.Red < 60, $"unexpected colour {pixel}");
    }

    [Fact]
    public void Png_sources_decode_at_their_own_size()
    {
        var source = ImageCrafting.Solid(1200, 900, SKColors.Teal);

        using var codec = UntrustedImageDecoding.OpenHeader(new MemoryStream(source), maxPixels: 50_000_000);
        using var bitmap = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(400, 300));

        Assert.Equal((1200, 900), (bitmap.Width, bitmap.Height));
    }

    [Fact]
    public void Cover_mode_decodes_at_least_the_box_on_both_sides()
    {
        var source = ImageCrafting.Solid(4000, 400, SKColors.Teal, SKEncodedImageFormat.Jpeg);

        using var codec = UntrustedImageDecoding.OpenHeader(new MemoryStream(source), maxPixels: 50_000_000);
        using var bitmap = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(1200, 630), cover: true);

        Assert.True(bitmap.Height >= 400 && bitmap.Width >= 1200, $"decoded {bitmap.Width}x{bitmap.Height}");
    }

    [Theory]
    [InlineData(SKEncodedImageFormat.Png)]
    [InlineData(SKEncodedImageFormat.Jpeg)]
    [InlineData(SKEncodedImageFormat.Webp)]
    public void Pixel_budget_is_enforced_from_the_header(SKEncodedImageFormat format)
    {
        var source = ImageCrafting.Solid(300, 200, SKColors.Teal, format);

        var error = Assert.Throws<PreviewSourceRejectedException>(() =>
            UntrustedImageDecoding.OpenHeader(new MemoryStream(source), maxPixels: 50_000));

        Assert.Contains("300x200", error.Message);
        Assert.Contains("pixel budget", error.Message);
    }

    [Fact]
    public void Png_with_many_compressed_text_chunks_is_rejected_before_any_codec_is_created()
    {
        // 100 zTXt chunks of 4 MB zeros each: about 400 KB on disk, about 400 MB once libpng has inflated them.
        var png = ImageCrafting.PngWithCompressedTextChunks(count: 100);
        Assert.InRange(png.Length, 100_000, 1_000_000);

        // The pure byte scan refuses it (no codec involved), and so does the public entry point.
        Assert.Equal("PNG contains a compressed zTXt chunk", UntrustedImageDecoding.RejectPngHeader(new MemoryStream(png), 50_000_000));
        var error = Assert.Throws<PreviewSourceRejectedException>(() =>
            UntrustedImageDecoding.OpenHeader(new MemoryStream(png), maxPixels: 50_000_000));
        Assert.Equal("PNG contains a compressed zTXt chunk", error.Message);
    }

    [Fact]
    public void Png_scan_fails_closed_on_compressed_profiles_text_and_oversized_or_truncated_chunk_layouts()
    {
        var budget = 50_000_000L;
        string? Scan(byte[] png) => UntrustedImageDecoding.RejectPngHeader(new MemoryStream(png), budget);

        Assert.Null(Scan(ImageCrafting.PngWithChunks(("tEXt", "Comment\0hello"u8.ToArray()))));
        Assert.Null(Scan(ImageCrafting.PngWithChunks(("iTXt", ImageCrafting.Itxt("Title", compressed: false, "plain")))));
        Assert.Null(Scan(ImageCrafting.PngWithChunks(("iCCP", "p\0\0x"u8.ToArray()))));
        Assert.Equal("PNG contains a compressed iTXt chunk", Scan(ImageCrafting.PngWithChunks(("iTXt", ImageCrafting.Itxt("Title", compressed: true, "zz")))));
        Assert.Equal("PNG contains a second iCCP chunk", Scan(ImageCrafting.PngWithChunks(("iCCP", "p\0\0x"u8.ToArray()), ("iCCP", "q\0\0x"u8.ToArray()))));
        Assert.Equal($"PNG carries more than {UntrustedImageDecoding.MaxPngAncillaryBytes} bytes of ancillary chunks",
            Scan(ImageCrafting.PngWithChunks(("tEXt", new byte[40_000]), ("tEXt", new byte[40_000]))));

        var truncated = ImageCrafting.PngWithChunks(("tEXt", new byte[100]))[..^20];
        Assert.Equal("PNG chunk runs past the end of the file", Scan(truncated));
        var noIend = ImageCrafting.PngWithChunks()[..^12];
        Assert.Equal("PNG ends before its IEND chunk", Scan(noIend));
    }

    [Fact]
    public void Jpeg_with_a_large_but_allowed_app_segment_still_decodes()
    {
        var jpeg = ImageCrafting.JpegWithAppSegment(64, 48, new SKColor(200, 40, 40), appBytes: 60_000);

        using var codec = UntrustedImageDecoding.OpenHeader(new MemoryStream(jpeg), maxPixels: 50_000_000);
        using var bitmap = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(400, 300));

        Assert.Equal((64, 48), (bitmap.Width, bitmap.Height));
        Assert.True(bitmap.IsImmutable);
        var pixel = bitmap.GetPixel(32, 24);
        Assert.True(pixel.Red > 150 && pixel.Blue < 100, $"unexpected colour {pixel}");
    }

    [Theory]
    [InlineData("not an image at all")]
    [InlineData("<svg xmlns='http://www.w3.org/2000/svg'/>")]
    [InlineData("II*\0\u0008\0\0\0")]
    public void Unknown_magic_bytes_are_refused_without_native_parsing(string head)
    {
        var error = Assert.Throws<PreviewSourceRejectedException>(() =>
            UntrustedImageDecoding.OpenHeader(new MemoryStream(System.Text.Encoding.Latin1.GetBytes(head)), maxPixels: 50_000_000));

        Assert.Equal("source is not a decodable image (unknown format)", error.Message);
    }

    [Fact]
    public void Animated_webp_decodes_its_first_frame_only()
    {
        var webp = ImageCrafting.AnimatedWebp(64, 48, new SKColor(220, 30, 30), new SKColor(30, 30, 220));

        using var codec = UntrustedImageDecoding.OpenHeader(new MemoryStream(webp), maxPixels: 50_000_000);
        Assert.Equal(2, codec.FrameCount);
        using var bitmap = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(400, 300));

        var pixel = bitmap.GetPixel(32, 24);
        Assert.True(pixel.Red > 150 && pixel.Blue < 100, $"expected the red first frame, got {pixel}");
    }

    [Fact]
    public void Disabled_formats_are_refused_from_the_header()
    {
        var error = Assert.Throws<PreviewSourceRejectedException>(() =>
            UntrustedImageDecoding.OpenHeader(new MemoryStream(ImageCrafting.Gif(10, 10)), maxPixels: 50_000_000));

        Assert.Contains("Gif is not an enabled format", error.Message);
    }
}
