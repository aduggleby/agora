using System.Text;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PDFtoImage;
using PDFtoImage.Exceptions;
using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using IOPath = System.IO.Path;

namespace Agora.Web.Services;

/// <summary>
/// Thrown when a preview source is refused before or during decoding (over the byte or pixel budget, not a decodable
/// image, or over the time budget). The message describes sizes only, never file content, so it is safe to log.
/// </summary>
public sealed class PreviewSourceRejectedException(string message) : Exception(message);

public sealed class SharePreviewImageGenerator
{
    private const int CanvasWidth = 960;
    private const int CanvasHeight = 720;
    private const int ContentMaxWidth = CanvasWidth - 56;
    private const int ContentMaxHeight = CanvasHeight - 90;

    // PDF pages are rasterized with the longer side at exactly this many pixels. Pages larger than the PDF
    // specification's maximum page size (14400 points on a side) are refused as a sanity cap.
    public const int PdfLongSidePixels = 1200;
    public const int PdfMaxPagePoints = 14400;

    // PDFium is native, synchronous and cannot be cancelled: cap how many renders run at once so renders abandoned
    // after a timeout occupy a slot (and block the next one) instead of piling up.
    private static readonly SemaphoreSlim PdfRenderSlots = new(2, 2);

    private static readonly Color White = Color.ParseHex("#FFFFFF");
    private static readonly Color Ink = Color.ParseHex("#1A1614");
    private static readonly Color InkLight = Color.ParseHex("#5C534A");
    private static readonly Color Border = Color.ParseHex("#E5DFD7");
    private static readonly Color Terra = Color.ParseHex("#C4663A");
    private static readonly object GenericPreviewSync = new();
    private static byte[]? _pendingPreviewBytes;
    private static byte[]? _unavailablePreviewBytes;

    private readonly AgoraPreviewOptions _limits;
    private readonly Configuration _decoderConfiguration;
    private readonly ILogger<SharePreviewImageGenerator> _logger;

    public SharePreviewImageGenerator(IOptions<AgoraOptions> options, ILogger<SharePreviewImageGenerator>? logger = null)
    {
        _limits = options.Value.Previews;
        _logger = logger ?? NullLogger<SharePreviewImageGenerator>.Instance;
        _decoderConfiguration = UntrustedImageDecoding.CreateConfiguration(_limits.MaxSourcePixels);
    }

    public Task<byte[]> GenerateForFileAsync(ShareFile file, string absolutePath, CancellationToken ct) =>
        WithTimeoutAsync(token => GenerateForFileCoreAsync(file, absolutePath, token), ct);

    private async Task<byte[]> GenerateForFileCoreAsync(ShareFile file, string absolutePath, CancellationToken ct)
    {
        var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();

        // The decoder is picked from the extension only (ContentTypePolicy), never from a stored or declared type.
        if (ContentTypePolicy.IsRasterImage(file.OriginalFilename))
        {
            using var source = await LoadBoundedImageAsync(absolutePath, new Size(ContentMaxWidth, ContentMaxHeight), ct);
            return await RenderContainedImageAsync(source, ct);
        }

        if (ContentTypePolicy.FromFileName(file.OriginalFilename) == "application/pdf")
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

    public Task<byte[]> GenerateMosaicThumbnailAsync(string absolutePath, int maxHeight, CancellationToken ct) =>
        WithTimeoutAsync(async token =>
        {
            using var source = await LoadBoundedImageAsync(absolutePath, new Size(maxHeight * 8, maxHeight), token);
            FitWithin(source, new Size(maxHeight * 8, maxHeight));

            await using var output = new MemoryStream();
            await source.SaveAsJpegAsync(output, new JpegEncoder { Quality = 82 }, token);
            return output.ToArray();
        }, ct);

    /// <summary>
    /// Runs <paramref name="work"/> under the configured time budget. A timeout surfaces as
    /// <see cref="PreviewSourceRejectedException"/>; cancellation of <paramref name="ct"/> itself propagates unchanged.
    /// </summary>
    private async Task<T> WithTimeoutAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _limits.TimeoutSeconds)));
        try
        {
            return await work(timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new PreviewSourceRejectedException($"generation exceeded the {_limits.TimeoutSeconds}s time budget");
        }
    }

    /// <summary>
    /// Opens an uploaded image within the budgets: the byte size is checked first, then the header (via
    /// <see cref="Image.IdentifyAsync(DecoderOptions, string, CancellationToken)"/>) against the pixel budget, and only
    /// then is a single frame decoded, scaled down to <paramref name="targetSize"/> where the format allows it.
    /// </summary>
    private async Task<Image<Rgba32>> LoadBoundedImageAsync(string absolutePath, Size targetSize, CancellationToken ct)
    {
        EnsureWithinByteBudget(absolutePath);
        await using (var header = File.OpenRead(absolutePath))
        {
            if (UntrustedImageDecoding.RejectPngHeader(header, _limits.MaxSourcePixels) is { } reason)
            {
                throw new PreviewSourceRejectedException(reason);
            }
        }

        ImageInfo info;
        try
        {
            info = await Image.IdentifyAsync(UntrustedImageDecoding.CreateDecoderOptions(_decoderConfiguration), absolutePath, ct);
        }
        catch (ImageFormatException ex)
        {
            throw new PreviewSourceRejectedException($"source is not a decodable image ({ex.GetType().Name})");
        }

        var pixels = (long)info.Width * info.Height;
        if (pixels > _limits.MaxSourcePixels)
        {
            throw new PreviewSourceRejectedException(
                $"source is {info.Width}x{info.Height} ({pixels} pixels), above the {_limits.MaxSourcePixels} pixel budget");
        }

        // TargetSize would also upscale a small source to the box; only ask for it when the source is larger.
        var decodeTarget = info.Width > targetSize.Width || info.Height > targetSize.Height ? targetSize : (Size?)null;
        try
        {
            return await Image.LoadAsync<Rgba32>(UntrustedImageDecoding.CreateDecoderOptions(_decoderConfiguration, decodeTarget), absolutePath, ct);
        }
        catch (ImageFormatException ex)
        {
            throw new PreviewSourceRejectedException($"source is not a decodable image ({ex.GetType().Name})");
        }
    }

    private void EnsureWithinByteBudget(string absolutePath)
    {
        var length = new FileInfo(absolutePath).Length;
        if (length > _limits.MaxSourceBytes)
        {
            throw new PreviewSourceRejectedException($"source is {length} bytes, above the {_limits.MaxSourceBytes} byte budget");
        }
    }

    /// <summary>
    /// Renders page one of a PDF at a bounded size. Returns null when PDFium cannot render the file (the caller falls
    /// back to the generic preview); budget violations throw <see cref="PreviewSourceRejectedException"/>.
    /// </summary>
    private async Task<byte[]?> TryRenderPdfFirstPageAsync(string absolutePath, CancellationToken ct)
    {
        EnsureWithinByteBudget(absolutePath);

        // Waiting for a slot counts against the time budget, so a backlog of stuck renders rejects new work promptly.
        await PdfRenderSlots.WaitAsync(ct);
        var render = Task.Run(() =>
        {
            try
            {
                return RenderPdfFirstPageBounded(absolutePath);
            }
            finally
            {
                PdfRenderSlots.Release();
            }
        }, CancellationToken.None);

        byte[] rendered;
        try
        {
            rendered = await render.WaitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("PDF render abandoned after the preview time budget; it keeps its render slot until PDFium returns");
            throw;
        }
        catch (Exception ex) when (IsPdfInputError(ex))
        {
            return null;
        }

        try
        {
            await using var pdfImageStream = new MemoryStream(rendered);
            using var source = await Image.LoadAsync<Rgba32>(UntrustedImageDecoding.CreateDecoderOptions(_decoderConfiguration), pdfImageStream, ct);
            return await RenderContainedImageAsync(source, ct);
        }
        catch (ImageFormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Errors PDFium/PDFtoImage raise for a bad document (and the empty-page guard below). Anything else, such as an
    /// IO failure reading the scratch copy, is infrastructure and must propagate so the job is retried.
    /// </summary>
    private static bool IsPdfInputError(Exception ex) =>
        ex is PdfException or ArgumentException or InvalidOperationException;

    /// <summary>
    /// Rasterizes page one of a PDF as JPEG with the longer side at <see cref="PdfLongSidePixels"/> pixels (aspect ratio
    /// preserved). Pages with a side above <see cref="PdfMaxPagePoints"/> points throw <see cref="PreviewSourceRejectedException"/>.
    /// Public so tests can check the intermediate raster size; the caller is responsible for byte budget and timeout.
    /// </summary>
    public static byte[] RenderPdfFirstPageBounded(string absolutePath)
    {
        using var pdf = File.OpenRead(absolutePath);
        var pageSize = Conversion.GetPageSize(pdf, page: 0, leaveOpen: true);
        if (!(pageSize.Width > 0) || !(pageSize.Height > 0))
        {
            throw new InvalidOperationException("PDF page has no size.");
        }

        if (Math.Max(pageSize.Width, pageSize.Height) > PdfMaxPagePoints)
        {
            throw new PreviewSourceRejectedException(
                $"PDF page is {pageSize.Width:0}x{pageSize.Height:0} points, above the {PdfMaxPagePoints} point sanity cap");
        }

        var options = pageSize.Width >= pageSize.Height
            ? new RenderOptions(Width: PdfLongSidePixels, WithAspectRatio: true)
            : new RenderOptions(Height: PdfLongSidePixels, WithAspectRatio: true);

        pdf.Position = 0;
        using var output = new MemoryStream();
        Conversion.SaveJpeg(output, pdf, page: 0, leaveOpen: true, password: null, options: options);
        return output.ToArray();
    }

    /// <summary>
    /// Scales <paramref name="image"/> in either direction so it fits <paramref name="box"/> exactly on one side,
    /// keeping the aspect ratio: a 40x30 source fills the box, while an extreme strip such as 2400x1 is bounded by the
    /// box width (never 720000x300). Dimensions never drop below 1.
    /// </summary>
    private static void FitWithin(Image<Rgba32> image, Size box)
    {
        var scale = Math.Min((double)box.Width / image.Width, (double)box.Height / image.Height);
        var width = Math.Max(1, (int)Math.Round(image.Width * scale));
        var height = Math.Max(1, (int)Math.Round(image.Height * scale));
        if (width == image.Width && height == image.Height)
        {
            return;
        }

        image.Mutate(ctx => ctx.Resize(width, height, KnownResamplers.Bicubic));
    }

    private async Task<byte[]> RenderContainedImageAsync(Image<Rgba32> source, CancellationToken ct)
    {
        using var canvas = new Image<Rgba32>(CanvasWidth, CanvasHeight, White);

        FitWithin(source, new Size(ContentMaxWidth, ContentMaxHeight));

        var x = (CanvasWidth - source.Width) / 2;
        var y = 20 + (ContentMaxHeight - source.Height) / 2;
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
        var ext = (IOPath.GetExtension(fileName) ?? string.Empty).Trim().ToLowerInvariant();
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
