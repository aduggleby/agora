using System.Text;
using Agora.Domain.Entities;
using PDFtoImage;
using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace Agora.Web.Services;

public sealed class SharePreviewImageGenerator
{
    private const int CanvasWidth = 960;
    private const int CanvasHeight = 720;

    private static readonly Color Cream = Color.ParseHex("#FAF7F2");
    private static readonly Color Ink = Color.ParseHex("#1A1614");
    private static readonly Color InkLight = Color.ParseHex("#5C534A");
    private static readonly Color Border = Color.ParseHex("#E5DFD7");
    private static readonly Color Terra = Color.ParseHex("#C4663A");

    public async Task<byte[]> GenerateForFileAsync(ShareFile file, string absolutePath, CancellationToken ct)
    {
        var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();

        if (renderType == "image")
        {
            using var source = await Image.LoadAsync<Rgba32>(absolutePath, ct);
            return await RenderContainedImageAsync(source, file.OriginalFilename, ct);
        }

        if (renderType == "pdf" || Path.GetExtension(file.OriginalFilename).Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            var pdfPreview = await TryRenderPdfFirstPageAsync(absolutePath, ct);
            if (pdfPreview is not null)
            {
                return pdfPreview;
            }
        }

        if (renderType == "text" || LooksLikeTextFile(file.OriginalFilename))
        {
            var snippet = await ReadTextSnippetAsync(absolutePath, ct);
            return await RenderTextPreviewAsync(file.OriginalFilename, snippet, ct);
        }

        return await RenderGenericPreviewAsync(file.OriginalFilename, "Preview", ct);
    }

    public Task<byte[]> GeneratePendingPreviewAsync(string fileName, CancellationToken ct)
    {
        return RenderGenericPreviewAsync(fileName, "Preview is being generated...", ct);
    }

    public Task<byte[]> GenerateUnavailablePreviewAsync(string fileName, CancellationToken ct)
    {
        return RenderGenericPreviewAsync(fileName, "Preview unavailable", ct);
    }

    private async Task<byte[]?> TryRenderPdfFirstPageAsync(string absolutePath, CancellationToken ct)
    {
        try
        {
            var pdfBytes = await File.ReadAllBytesAsync(absolutePath, ct);
            await using var pdfImageStream = new MemoryStream();
            Conversion.SaveJpeg(pdfImageStream, pdfBytes, 0);
            pdfImageStream.Position = 0;
            using var source = await Image.LoadAsync<Rgba32>(pdfImageStream, ct);
            return await RenderContainedImageAsync(source, Path.GetFileName(absolutePath), ct);
        }
        catch
        {
            return null;
        }
    }

    private async Task<byte[]> RenderContainedImageAsync(Image<Rgba32> source, string fileName, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, Cream);
        var maxWidth = CanvasWidth - 56;
        var maxHeight = CanvasHeight - 90;

        source.Mutate(ctx => ctx.Resize(new ResizeOptions
        {
            Size = new Size(maxWidth, maxHeight),
            Mode = ResizeMode.Max,
            Sampler = KnownResamplers.Bicubic
        }));

        var x = (CanvasWidth - source.Width) / 2;
        var y = 20 + (maxHeight - source.Height) / 2;
        canvas.Mutate(ctx =>
        {
            ctx.Fill(new LinearGradientBrush(
                new PointF(0, 0),
                new PointF(CanvasWidth, CanvasHeight),
                GradientRepetitionMode.None,
                new ColorStop(0, new Color(new Rgba32(196, 102, 58, 10))),
                new ColorStop(1, Color.Transparent)),
                new RectangleF(0, 0, CanvasWidth, CanvasHeight));
            ctx.DrawImage(source, new Point(x, y), 1f);
            ctx.Draw(Border, 1f, new RectangleF(10, 10, CanvasWidth - 20, CanvasHeight - 20));
            ctx.Fill(Terra, new RectangleF(0, CanvasHeight - 42, CanvasWidth, 42));
            ctx.DrawText(new RichTextOptions(PickFont(16, FontStyle.Bold))
            {
                Origin = new PointF(16, CanvasHeight - 28),
                WrappingLength = CanvasWidth - 32
            },
            Truncate(fileName, 80), Color.White);
        });

        await using var output = new MemoryStream();
        await canvas.SaveAsJpegAsync(output, new JpegEncoder { Quality = 84 }, ct);
        return output.ToArray();
    }

    private async Task<byte[]> RenderTextPreviewAsync(string fileName, string text, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, Cream);
        var titleFont = PickFont(20, FontStyle.Bold);
        var bodyFont = PickFont(18, FontStyle.Regular);

        canvas.Mutate(ctx =>
        {
            ctx.Fill(new Color(new Rgba32(196, 102, 58, 20)), new RectangleF(0, 0, CanvasWidth, 64));
            ctx.DrawText(new RichTextOptions(titleFont)
            {
                Origin = new PointF(20, 22),
                WrappingLength = CanvasWidth - 40
            }, Truncate(fileName, 90), Ink);

            ctx.Fill(Color.White, new RectangleF(20, 82, CanvasWidth - 40, CanvasHeight - 112));
            ctx.Draw(Border, 1f, new RectangleF(20, 82, CanvasWidth - 40, CanvasHeight - 112));
            ctx.DrawText(new RichTextOptions(bodyFont)
            {
                Origin = new PointF(34, 104),
                WrappingLength = CanvasWidth - 68,
                VerticalAlignment = VerticalAlignment.Top,
                HorizontalAlignment = HorizontalAlignment.Left
            }, NormalizeText(text), InkLight);
        });

        await using var output = new MemoryStream();
        await canvas.SaveAsJpegAsync(output, new JpegEncoder { Quality = 85 }, ct);
        return output.ToArray();
    }

    private async Task<byte[]> RenderGenericPreviewAsync(string fileName, string message, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, Cream);
        var ext = Path.GetExtension(fileName).Trim().TrimStart('.').ToUpperInvariant();
        if (string.IsNullOrWhiteSpace(ext))
        {
            ext = "FILE";
        }

        canvas.Mutate(ctx =>
        {
            ctx.Fill(new LinearGradientBrush(
                new PointF(0, 0),
                new PointF(CanvasWidth, CanvasHeight),
                GradientRepetitionMode.None,
                new ColorStop(0, new Color(new Rgba32(196, 102, 58, 22))),
                new ColorStop(1, Color.Transparent)),
                new RectangleF(0, 0, CanvasWidth, CanvasHeight));
            ctx.Fill(Color.White, new RectangleF(70, 90, CanvasWidth - 140, CanvasHeight - 180));
            ctx.Draw(Border, 1f, new RectangleF(70, 90, CanvasWidth - 140, CanvasHeight - 180));
            ctx.DrawText(new RichTextOptions(PickFont(52, FontStyle.Bold))
            {
                Origin = new PointF(CanvasWidth / 2f, 290),
                HorizontalAlignment = HorizontalAlignment.Center
            }, ext, Terra);
            ctx.DrawText(new RichTextOptions(PickFont(22, FontStyle.Bold))
            {
                Origin = new PointF(CanvasWidth / 2f, 360),
                HorizontalAlignment = HorizontalAlignment.Center,
                WrappingLength = CanvasWidth - 220
            }, Truncate(fileName, 70), Ink);
            ctx.DrawText(new RichTextOptions(PickFont(18, FontStyle.Regular))
            {
                Origin = new PointF(CanvasWidth / 2f, 410),
                HorizontalAlignment = HorizontalAlignment.Center,
                WrappingLength = CanvasWidth - 220
            }, message, InkLight);
        });

        await using var output = new MemoryStream();
        await canvas.SaveAsJpegAsync(output, new JpegEncoder { Quality = 85 }, ct);
        return output.ToArray();
    }

    private static bool LooksLikeTextFile(string fileName)
    {
        var ext = (Path.GetExtension(fileName) ?? string.Empty).Trim().ToLowerInvariant();
        return ext is ".txt" or ".md" or ".csv" or ".json" or ".xml" or ".yaml" or ".yml" or ".log";
    }

    private static async Task<string> ReadTextSnippetAsync(string absolutePath, CancellationToken ct)
    {
        var builder = new StringBuilder(1024);
        await using var stream = File.OpenRead(absolutePath);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);

        var buffer = new char[256];
        while (builder.Length < 1000)
        {
            var needed = Math.Min(buffer.Length, 1000 - builder.Length);
            var count = await reader.ReadAsync(buffer.AsMemory(0, needed), ct);
            if (count == 0)
            {
                break;
            }

            builder.Append(buffer, 0, count);
        }

        return builder.ToString();
    }

    private static Font PickFont(float size, FontStyle style)
    {
        var families = new[] { "DM Sans", "DejaVu Sans", "Arial", "Liberation Sans" };
        foreach (var family in families)
        {
            if (SystemFonts.TryGet(family, out var fontFamily))
            {
                return fontFamily.CreateFont(size, style);
            }
        }

        return SystemFonts.Collection.Families.First().CreateFont(size, style);
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Length <= maxLength ? value : value[..(maxLength - 1)] + "...";
    }

    private static string NormalizeText(string text)
    {
        var normalized = (text ?? string.Empty)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Replace('\t', ' ')
            .Trim();

        if (normalized.Length == 0)
        {
            return "(empty text file)";
        }

        return normalized;
    }
}
