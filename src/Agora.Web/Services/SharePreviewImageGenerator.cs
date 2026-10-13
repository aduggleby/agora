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

    private static readonly Color White = Color.ParseHex("#FFFFFF");
    private static readonly Color Ink = Color.ParseHex("#1A1614");
    private static readonly Color InkLight = Color.ParseHex("#5C534A");
    private static readonly Color Border = Color.ParseHex("#E5DFD7");
    private static readonly Color Terra = Color.ParseHex("#C4663A");
    private static readonly object GenericPreviewSync = new();
    private static byte[]? _pendingPreviewBytes;
    private static byte[]? _unavailablePreviewBytes;

    public async Task<byte[]> GenerateForFileAsync(ShareFile file, string absolutePath, CancellationToken ct)
    {
        var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();

        if (renderType == "image")
        {
            using var source = await Image.LoadAsync<Rgba32>(absolutePath, ct);
            return await RenderContainedImageAsync(source, ct);
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
            return await RenderTextPreviewAsync(snippet, ct);
        }

        return await GenerateUnavailablePreviewAsync(ct);
    }

    public Task<byte[]> GeneratePendingPreviewAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(GetOrCreatePendingPreviewBytes());
    }

    public Task<byte[]> GenerateUnavailablePreviewAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(GetOrCreateUnavailablePreviewBytes());
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
            return await RenderContainedImageAsync(source, ct);
        }
        catch
        {
            return null;
        }
    }

    public async Task<byte[]> GenerateMosaicThumbnailAsync(string absolutePath, int maxHeight, CancellationToken ct)
    {
        using var source = await Image.LoadAsync<Rgba32>(absolutePath, ct);

        source.Mutate(ctx => ctx.Resize(new ResizeOptions
        {
            Size = new Size(0, maxHeight),
            Mode = ResizeMode.Max,
            Sampler = KnownResamplers.Bicubic
        }));

        await using var output = new MemoryStream();
        await source.SaveAsJpegAsync(output, new JpegEncoder { Quality = 82 }, ct);
        return output.ToArray();
    }

    private async Task<byte[]> RenderContainedImageAsync(Image<Rgba32> source, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, White);
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
            ctx.DrawImage(source, new Point(x, y), 1f);
        });

        await using var output = new MemoryStream();
        await canvas.SaveAsJpegAsync(output, new JpegEncoder { Quality = 84 }, ct);
        return output.ToArray();
    }

    private async Task<byte[]> RenderTextPreviewAsync(string text, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, White);
        var bodyFont = PickFont(18, FontStyle.Regular);

        canvas.Mutate(ctx =>
        {
            ctx.Fill(Color.White, new RectangleF(20, 20, CanvasWidth - 40, CanvasHeight - 40));
            ctx.Draw(Border, 1f, new RectangleF(20, 20, CanvasWidth - 40, CanvasHeight - 40));
            ctx.DrawText(new RichTextOptions(bodyFont)
            {
                Origin = new PointF(34, 36),
                WrappingLength = CanvasWidth - 68,
                VerticalAlignment = VerticalAlignment.Top,
                HorizontalAlignment = HorizontalAlignment.Left
            }, NormalizeText(text), InkLight);
        });

        await using var output = new MemoryStream();
        await canvas.SaveAsJpegAsync(output, new JpegEncoder { Quality = 85 }, ct);
        return output.ToArray();
    }

    private static byte[] GetOrCreatePendingPreviewBytes()
    {
        if (_pendingPreviewBytes is not null)
        {
            return _pendingPreviewBytes;
        }

        lock (GenericPreviewSync)
        {
            _pendingPreviewBytes ??= RenderGenericStatusPreview("Preparing preview...");
            return _pendingPreviewBytes;
        }
    }

    private static byte[] GetOrCreateUnavailablePreviewBytes()
    {
        if (_unavailablePreviewBytes is not null)
        {
            return _unavailablePreviewBytes;
        }

        lock (GenericPreviewSync)
        {
            _unavailablePreviewBytes ??= RenderGenericStatusPreview("Preview cannot be shown for this file type.");
            return _unavailablePreviewBytes;
        }
    }

    private static byte[] RenderGenericStatusPreview(string message)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, White);

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
            }, "PREVIEW", Terra);
            ctx.DrawText(new RichTextOptions(PickFont(18, FontStyle.Regular))
            {
                Origin = new PointF(CanvasWidth / 2f, 380),
                HorizontalAlignment = HorizontalAlignment.Center,
                WrappingLength = CanvasWidth - 220
            }, message, InkLight);
        });

        using var output = new MemoryStream();
        canvas.SaveAsJpeg(output, new JpegEncoder { Quality = 85 });
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
