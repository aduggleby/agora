using System.Text;
using Agora.Application.Models;
using Agora.Domain.Entities;
using Agora.Web.Services;
using Microsoft.Extensions.Options;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

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

        using var previewImage = Image.Load<Rgba32>(preview);
        Assert.Equal(960, previewImage.Width);
        Assert.Equal(720, previewImage.Height);
        using var thumbnailImage = Image.Load<Rgba32>(thumbnail);
        Assert.True(thumbnailImage.Height <= 300);
        Assert.True(thumbnailImage.Width > 0);
        Assert.NotEqual(await generator.GenerateUnavailablePreviewAsync(Ct), preview);
    }

    [Fact]
    public async Task Pdf_first_page_is_rendered_within_the_canvas()
    {
        var path = await WriteAsync("doc.pdf", MinimalPdf(200, 100));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await generator.GenerateForFileAsync(PdfFile("doc.pdf"), path, Ct);

        using var previewImage = Image.Load<Rgba32>(preview);
        Assert.Equal(960, previewImage.Width);
        Assert.Equal(720, previewImage.Height);
        Assert.NotEqual(await generator.GenerateUnavailablePreviewAsync(Ct), preview);
    }

    [Fact]
    public async Task Tall_pdf_page_is_rasterized_with_the_long_side_at_1200_pixels()
    {
        var path = await WriteAsync("tall.pdf", MinimalPdf(100, 1000));

        var raster = SharePreviewImageGenerator.RenderPdfFirstPageBounded(path);

        using var image = Image.Load<Rgba32>(raster);
        Assert.Equal(SharePreviewImageGenerator.PdfLongSidePixels, image.Height);
        Assert.Equal(120, image.Width);
    }

    [Fact]
    public async Task Wide_pdf_page_is_rasterized_with_the_long_side_at_1200_pixels()
    {
        var path = await WriteAsync("wide.pdf", MinimalPdf(3000, 300));

        var raster = SharePreviewImageGenerator.RenderPdfFirstPageBounded(path);

        using var image = Image.Load<Rgba32>(raster);
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
    public async Task Gif_source_is_rejected_cleanly_as_an_unknown_format()
    {
        var path = await WriteAsync("anim.gif", await SmallImageAsync(save: (image, stream) => image.SaveAsGifAsync(stream)));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var preview = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateForFileAsync(ImageFile("anim.gif"), path, Ct));
        var thumbnail = await Assert.ThrowsAsync<PreviewSourceRejectedException>(() =>
            generator.GenerateMosaicThumbnailAsync(path, 300, Ct));

        Assert.Contains("not a decodable image", preview.Message);
        Assert.Contains("not a decodable image", thumbnail.Message);
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

        using var previewImage = Image.Load<Rgba32>(preview);
        Assert.Equal(960, previewImage.Width);
        Assert.Equal(720, previewImage.Height);
        using var thumbnailImage = Image.Load<Rgba32>(thumbnail);
        Assert.True(thumbnailImage.Width <= 2400, $"thumbnail width {thumbnailImage.Width}");
        Assert.True(thumbnailImage.Height <= 300, $"thumbnail height {thumbnailImage.Height}");
        // Bounded by the box side the strip runs along: 2400x1 stays 2400 wide, 1x2400 becomes 300 tall.
        Assert.Equal(width > height ? 2400 : 300, width > height ? thumbnailImage.Width : thumbnailImage.Height);
    }

    [Fact]
    public async Task Small_sources_are_scaled_up_to_fit_the_thumbnail_box()
    {
        var path = await WriteAsync("photo.png", await SmallImageAsync(40, 30));
        var generator = CreateGenerator(new AgoraPreviewOptions());

        var thumbnail = await generator.GenerateMosaicThumbnailAsync(path, 300, Ct);

        // The 2400x300 box is height-limited for a 4:3 source: 400x300, as before the budgets were added.
        using var thumbnailImage = Image.Load<Rgba32>(thumbnail);
        Assert.Equal(400, thumbnailImage.Width);
        Assert.Equal(300, thumbnailImage.Height);
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

    private static async Task<byte[]> SmallImageAsync(int width = 40, int height = 30, Func<Image<Rgba32>, Stream, Task>? save = null)
    {
        using var image = new Image<Rgba32>(width, height, new Rgba32(200, 100, 50));
        using var output = new MemoryStream();
        await (save ?? ((img, stream) => img.SaveAsPngAsync(stream)))(image, output);
        return output.ToArray();
    }

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
