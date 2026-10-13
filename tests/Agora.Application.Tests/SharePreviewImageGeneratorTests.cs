using System.Text;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Web.Services;
using Microsoft.Extensions.Options;
using SkiaSharp;

namespace Agora.Application.Tests;

/// <summary>
/// Budgets around preview generation: sources are refused by byte size and by header dimensions before any pixel is
/// decoded, PDFs are rasterized at a bounded size, and ordinary small sources still produce a preview and thumbnail.
/// </summary>
public sealed class SharePreviewImageGeneratorTests : IDisposable
{
    private static readonly CancellationToken Ct = CancellationToken.None;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "agora-preview-tests", Guid.NewGuid().ToString("N"));

    public SharePreviewImageGeneratorTests() => Directory.CreateDirectory(_root);

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public async Task Image_above_the_pixel_budget_is_rejected_from_the_header_before_decoding()
    {
        // A syntactically valid PNG header declaring 30000x30000 with no image data at all: identifying it works,
        // decoding it would fail with an image format error, so a pixel-budget rejection proves no decode ran.
        var path = await WriteAsync("huge.png", PngCrafting.HeaderOnly(30_000, 30_000));
        var generator = CreateGenerator(new AgoraPreviewOptions { MaxSourcePixels = 50_000_000 });

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("huge.png"), path, Ct));

        Assert.Contains("pixel budget", error.Message);
        Assert.Contains("30000x30000", error.Message);
    }

    [Fact]
    public async Task Thumbnail_source_above_the_pixel_budget_is_rejected_before_decoding()
    {
        var path = await WriteAsync("huge.png", PngCrafting.HeaderOnly(30_000, 30_000));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateMosaicThumbnailAsync(path, 300, Ct));

        Assert.Contains("pixel budget", error.Message);
    }

    [Fact]
    public async Task Image_above_the_byte_budget_is_rejected()
    {
        var path = await WriteAsync("photo.png", await SmallPngAsync());
        var generator = CreateGenerator(new AgoraPreviewOptions { MaxSourceBytes = 10 });

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("photo.png"), path, Ct));

        Assert.Contains("byte budget", error.Message);
    }

    [Fact]
    public async Task Pdf_above_the_byte_budget_is_rejected()
    {
        var path = await WriteAsync("doc.pdf", MinimalPdf(200, 100));
        var generator = CreateGenerator(new AgoraPreviewOptions { MaxSourceBytes = 10 });

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(PdfFile("doc.pdf"), path, Ct));

        Assert.Contains("byte budget", error.Message);
    }

    [Fact]
    public async Task Undecodable_image_bytes_are_rejected_not_thrown_as_a_decoder_error()
    {
        var path = await WriteAsync("photo.png", Encoding.ASCII.GetBytes("this is not a png"));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("photo.png"), path, Ct));

        Assert.Contains("not a decodable image", error.Message);
    }

    [Fact]
    public async Task Small_png_produces_a_preview_and_a_thumbnail()
    {
        var path = await WriteAsync("photo.png", await SmallPngAsync());
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(ImageFile("photo.png"), path, Ct);
        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        Assert.Equal((960, 720), ImageCrafting.Dimensions(preview));
        var thumbnailSize = ImageCrafting.Dimensions(thumbnail);
        Assert.True(thumbnailSize.Height <= 300);
        Assert.True(thumbnailSize.Width > 0);
        Assert.NotEqual(await generator.GenerateUnavailablePreviewAsync(Ct), preview);
    }

    [Fact]
    public async Task Pdf_first_page_is_rendered_within_the_canvas()
    {
        var path = await WriteAsync("doc.pdf", MinimalPdf(200, 100));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(PdfFile("doc.pdf"), path, Ct);

        Assert.Equal((960, 720), ImageCrafting.Dimensions(preview));
        Assert.NotEqual(await generator.GenerateUnavailablePreviewAsync(Ct), preview);
        // The page's orange rectangle (0.8 0.4 0.2) covers the centre of the content box.
        var centre = ImageCrafting.Pixel(preview, 480, 335);
        Assert.True(centre.Red > 150 && centre.Blue < 120, $"expected the orange page content at the centre, got {centre}");
    }

    [Fact]
    public async Task Tall_pdf_page_is_rasterized_with_the_long_side_at_1200_pixels()
    {
        var path = await WriteAsync("tall.pdf", MinimalPdf(100, 1000));

        using var image = SharePreviewImageGenerator.RenderPdfFirstPageBounded(path);

        Assert.Equal(SharePreviewImageGenerator.PdfLongSidePixels, image.Height);
        Assert.Equal(120, image.Width);
    }

    [Fact]
    public async Task Wide_pdf_page_is_rasterized_with_the_long_side_at_1200_pixels()
    {
        var path = await WriteAsync("wide.pdf", MinimalPdf(3000, 300));

        using var image = SharePreviewImageGenerator.RenderPdfFirstPageBounded(path);

        Assert.Equal(SharePreviewImageGenerator.PdfLongSidePixels, image.Width);
        Assert.Equal(120, image.Height);
    }

    [Fact]
    public async Task Pdf_page_above_the_point_sanity_cap_is_rejected()
    {
        var path = await WriteAsync("giant.pdf", MinimalPdf(100, SharePreviewImageGenerator.PdfMaxPagePoints + 1000));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(PdfFile("giant.pdf"), path, Ct));

        Assert.Contains("sanity cap", error.Message);
    }

    [Fact]
    public async Task Png_with_a_large_first_ihdr_and_a_tiny_last_ihdr_is_rejected_from_the_first_header()
    {
        // Identify would report the last IHDR (1x1) while the decoder allocates from the first (12000x12000).
        var path = await WriteAsync("double.png", PngCrafting.DoubleIhdr(12_000, 12_000, 1, 1));
        var generator = CreateGenerator(new AgoraPreviewOptions { MaxSourcePixels = 50_000_000 });

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("double.png"), path, Ct));

        Assert.Contains("12000x12000", error.Message);
        Assert.Contains("pixel budget", error.Message);
    }

    [Fact]
    public async Task Png_with_a_second_ihdr_is_rejected_even_within_the_pixel_budget()
    {
        var path = await WriteAsync("double.png", PngCrafting.DoubleIhdr(10, 10, 1, 1));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("double.png"), path, Ct));

        Assert.Contains("second IHDR", error.Message);
    }

    [Fact]
    public async Task Gif_source_is_rejected_cleanly_as_a_disabled_format()
    {
        var path = await WriteAsync("anim.gif", ImageCrafting.Gif(40, 30, frames: 1));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("anim.gif"), path, Ct));
        var thumbnail = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateMosaicThumbnailAsync(path, 300, Ct));

        Assert.Contains("not a decodable image", preview.Message);
        Assert.Contains("not a decodable image", thumbnail.Message);
    }

    [Fact]
    public async Task Animated_gif_with_restore_to_previous_frames_is_rejected_from_the_header()
    {
        // Within the pixel budget, so only the format gate can refuse it; the frames use disposal method 3, the mode
        // that would keep an extra full canvas alive per frame if it were decoded.
        var gif = ImageCrafting.Gif(4000, 4000, frames: 2);
        using (var codec = SKCodec.Create(new MemoryStream(gif)))
        {
            Assert.NotNull(codec);
            Assert.Equal(SKEncodedImageFormat.Gif, codec.EncodedFormat);
            Assert.Equal(2, codec.FrameCount);
            Assert.Equal(SKCodecAnimationDisposalMethod.RestorePrevious, codec.FrameInfo[1].DisposalMethod);
        }

        var path = await WriteAsync("anim.gif", gif);
        var generator = CreateGenerator(new AgoraPreviewOptions { MaxSourcePixels = 50_000_000 });

        var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("anim.gif"), path, Ct));

        Assert.Contains("Gif is not an enabled format", error.Message);
    }

    [Theory]
    [InlineData(2400, 1)]
    [InlineData(1, 2400)]
    public async Task Extreme_aspect_sources_produce_bounded_preview_and_thumbnail(int width, int height)
    {
        var path = await WriteAsync("strip.png", await SmallImageAsync(width, height));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(ImageFile("strip.png"), path, Ct);
        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        Assert.Equal((960, 720), ImageCrafting.Dimensions(preview));
        var thumbnailSize = ImageCrafting.Dimensions(thumbnail);
        Assert.True(thumbnailSize.Width <= 2400, $"thumbnail width {thumbnailSize.Width}");
        Assert.True(thumbnailSize.Height <= 300, $"thumbnail height {thumbnailSize.Height}");
        // Bounded by the box side the strip runs along: 2400x1 stays 2400 wide, 1x2400 becomes 300 tall.
        Assert.Equal(width > height ? 2400 : 300, width > height ? thumbnailSize.Width : thumbnailSize.Height);
    }

    [Fact]
    public async Task Small_sources_are_scaled_up_to_fit_the_thumbnail_box()
    {
        var path = await WriteAsync("photo.png", await SmallImageAsync(40, 30));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        // The 2400x300 box is height-limited for a 4:3 source: 400x300, as before the budgets were added.
        Assert.Equal((400, 300), ImageCrafting.Dimensions(thumbnail));
    }

    [Fact]
    public async Task Animated_webp_preview_and_thumbnail_show_the_first_frame()
    {
        var path = await WriteAsync("anim.webp", ImageCrafting.AnimatedWebp(64, 48, new SKColor(220, 30, 30), new SKColor(30, 30, 220)));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(ImageFile("anim.webp"), path, Ct);
        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        var previewCentre = ImageCrafting.Pixel(preview, 480, 335);
        Assert.True(previewCentre.Red > 150 && previewCentre.Blue < 100, $"preview shows {previewCentre}");
        Assert.Equal((400, 300), ImageCrafting.Dimensions(thumbnail));
        var thumbnailCentre = ImageCrafting.Pixel(thumbnail, 200, 150);
        Assert.True(thumbnailCentre.Red > 150 && thumbnailCentre.Blue < 100, $"thumbnail shows {thumbnailCentre}");
    }

    [Fact]
    public async Task Decode_waits_for_a_raster_slot_and_is_rejected_on_timeout_without_starting()
    {
        var path = await WriteAsync("photo.png", await SmallPngAsync());
        var generator = CreateGenerator(new AgoraPreviewOptions { TimeoutSeconds = 1 });
        var slots = SharePreviewImageGenerator.RasterDecodeSlots;

        // Hold both slots as two abandoned decodes would.
        await slots.WaitAsync(Ct);
        await slots.WaitAsync(Ct);
        try
        {
            var started = SharePreviewImageGenerator.RasterDecodesStarted;

            var error = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
                generator.GenerateMosaicThumbnailAsync(path, 300, Ct));

            Assert.Contains("time budget", error.Message);
            Assert.Equal(started, SharePreviewImageGenerator.RasterDecodesStarted);
            Assert.Equal(0, slots.CurrentCount);
        }
        finally
        {
            slots.Release(2);
        }

        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        Assert.Equal((400, 300), ImageCrafting.Dimensions(thumbnail));
        // Both slots come back once the workers exit (other test classes decode in parallel, so allow them to drain).
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (slots.CurrentCount < 2 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20, Ct);
        }

        Assert.Equal(2, slots.CurrentCount);
    }

    [Fact]
    public async Task Pdf_read_failure_propagates_instead_of_publishing_the_placeholder()
    {
        var path = await WriteAsync("doc.pdf", MinimalPdf(200, 100));
        File.SetUnixFileMode(path, UnixFileMode.None);
        var generator = CreateGenerator(new AgoraPreviewOptions());

        try
        {
            var error = await Record.ExceptionAsync(() => generator.GenerateForFileAsync(PdfFile("doc.pdf"), path, Ct));

            Assert.NotNull(error);
            Assert.IsNotType<PreviewSourceRejectedException>(error);
            Assert.True(error is UnauthorizedAccessException or IOException, error.GetType().FullName);
        }
        finally
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Fact]
    public async Task Corrupt_pdf_falls_back_to_the_placeholder_preview()
    {
        var path = await WriteAsync("doc.pdf", Encoding.ASCII.GetBytes("%PDF-1.4 this is not really a pdf"));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(PdfFile("doc.pdf"), path, Ct);

        Assert.Equal(await generator.GenerateUnavailablePreviewAsync(Ct), preview);
    }

    private static SharePreviewImageGenerator CreateGenerator(AgoraPreviewOptions previews) =>
        new(Options.Create(new AgoraOptions { Previews = previews }));

    private static ShareFile ImageFile(string name) => new()
    {
        Id = Guid.NewGuid(),
        OriginalFilename = name,
        StoredRelativePath = "shares/x/" + name,
        RenderType = "image"
    };

    private static ShareFile PdfFile(string name) => new()
    {
        Id = Guid.NewGuid(),
        OriginalFilename = name,
        StoredRelativePath = "shares/x/" + name,
        RenderType = "pdf"
    };

    private async Task<string> WriteAsync(string name, byte[] content)
    {
        var path = Path.Combine(_root, name);
        await File.WriteAllBytesAsync(path, content);
        return path;
    }

    private static Task<byte[]> SmallPngAsync() => SmallImageAsync(40, 30);

    private static Task<byte[]> SmallImageAsync(int width = 40, int height = 30) =>
        Task.FromResult(ImageCrafting.Solid(width, height, new SKColor(200, 100, 50)));

    /// <summary>A one-page PDF with a filled rectangle, with a correct cross-reference table.</summary>
    private static byte[] MinimalPdf(int width, int height)
    {
        var content = $"0.8 0.4 0.2 rg 10 10 {width - 20} {height - 20} re f";
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Contents 4 0 R >>",
            $"<< /Length {content.Length} >>\nstream\n{content}\nendstream"
        };

        var builder = new StringBuilder("%PDF-1.4\n");
        var offsets = new List<int>();
        for (var i = 0; i < objects.Length; i++)
        {
            offsets.Add(builder.Length);
            builder.Append($"{i + 1} 0 obj\n{objects[i]}\nendobj\n");
        }

        var xref = builder.Length;
        builder.Append($"xref\n0 {objects.Length + 1}\n0000000000 65535 f \n");
        foreach (var offset in offsets)
        {
            builder.Append($"{offset:D10} 00000 n \n");
        }

        builder.Append($"trailer\n<< /Size {objects.Length + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }
}
