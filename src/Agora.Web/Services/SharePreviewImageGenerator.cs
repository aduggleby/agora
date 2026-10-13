using System.Text;
using Agora.Application.Models;
using Agora.Application.Utilities;
using Agora.Domain.Entities;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PDFtoImage;
using PDFtoImage.Exceptions;
using SkiaSharp;
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
    // after a timeout occupy a slot (and block the next one) instead of piling up. Raster decodes get the same
    // treatment: Skia decodes synchronously and a decode abandoned after a timeout holds up to the pixel budget x 4
    // bytes until it returns. Internal so tests can hold the slots.
    private static readonly SemaphoreSlim PdfRenderSlots = new(2, 2);
    internal static readonly SemaphoreSlim RasterDecodeSlots = new(2, 2);
    private static long _rasterDecodesStarted;

    /// <summary>Number of raster decode workers that have started (for tests).</summary>
    internal static long RasterDecodesStarted => Interlocked.Read(ref _rasterDecodesStarted);

    private static readonly SKSamplingOptions Resampling = new(SKCubicResampler.Mitchell);

    private static readonly SKColor White = SKColors.White;
    private static readonly SKColor InkLight = SKColor.Parse("#5C534A");
    private static readonly SKColor Border = SKColor.Parse("#E5DFD7");
    private static readonly SKColor Terra = SKColor.Parse("#C4663A");
    private static readonly object GenericPreviewSync = new();
    private static byte[]? _pendingPreviewBytes;
    private static byte[]? _unavailablePreviewBytes;

    private readonly AgoraPreviewOptions _limits;
    private readonly BrandTypefaces _typefaces;
    private readonly ILogger<SharePreviewImageGenerator> _logger;

    public SharePreviewImageGenerator(IOptions<AgoraOptions> options, ILogger<SharePreviewImageGenerator>? logger = null, string? fontsDirectory = null)
    {
        _limits = options.Value.Previews;
        _logger = logger ?? NullLogger<SharePreviewImageGenerator>.Instance;
        _typefaces = new BrandTypefaces(fontsDirectory ?? BrandTypefaces.DefaultDirectory);
    }

    public Task<byte[]> GenerateForFileAsync(ShareFile file, string absolutePath, CancellationToken ct) =>
        WithTimeoutAsync(token => GenerateForFileCoreAsync(file, absolutePath, token), ct);

    private async Task<byte[]> GenerateForFileCoreAsync(ShareFile file, string absolutePath, CancellationToken ct)
    {
        var renderType = (file.RenderType ?? string.Empty).Trim().ToLowerInvariant();

        // The decoder is picked from the extension only (ContentTypePolicy), never from a stored or declared type.
        if (ContentTypePolicy.IsRasterImage(file.OriginalFilename))
        {
            return await RunBoundedAsync(() =>
            {
                using var source = LoadBoundedImage(absolutePath, new SKSizeI(ContentMaxWidth, ContentMaxHeight));
                return RenderContainedImage(source);
            }, ct);
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
            return RenderTextPreview(snippet);
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
        WithTimeoutAsync(token => RunBoundedAsync(() =>
        {
            var box = new SKSizeI(maxHeight * 8, maxHeight);
            using var source = LoadBoundedImage(absolutePath, box);
            var size = FitWithin(source.Info.Size, box);

            using var surface = SKSurface.Create(new SKImageInfo(size.Width, size.Height, SKColorType.Rgba8888, SKAlphaType.Premul));
            surface.Canvas.Clear(White);
            surface.Canvas.DrawBitmap(source, SKRect.Create(size.Width, size.Height), Resampling);
            return EncodeJpeg(surface, 82);
        }, token), ct);

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
    /// Runs a synchronous Skia decode/draw on the pool inside one of the <see cref="RasterDecodeSlots"/>; only the wait
    /// is cancellable. Waiting for a slot counts against the time budget, so with both slots held by abandoned work a
    /// new request is rejected on timeout without ever starting. The slot is released when the worker actually exits.
    /// </summary>
    private static async Task<T> RunBoundedAsync<T>(Func<T> work, CancellationToken ct)
    {
        await RasterDecodeSlots.WaitAsync(ct);
        if (ct.IsCancellationRequested)
        {
            RasterDecodeSlots.Release();
            ct.ThrowIfCancellationRequested();
        }

        var worker = Task.Run(() =>
        {
            Interlocked.Increment(ref _rasterDecodesStarted);
            try
            {
                return work();
            }
            finally
            {
                RasterDecodeSlots.Release();
            }
        }, CancellationToken.None);

        return await worker.WaitAsync(ct);
    }

    /// <summary>
    /// Opens an uploaded image within the budgets: the byte size is checked first, then the header (format and pixel
    /// budget, see <see cref="UntrustedImageDecoding"/>), and only then is the first frame decoded, scaled down during
    /// decoding towards <paramref name="targetBox"/> where the format allows it.
    /// </summary>
    private SKBitmap LoadBoundedImage(string absolutePath, SKSizeI targetBox)
    {
        EnsureWithinByteBudget(absolutePath);
        using var codec = UntrustedImageDecoding.OpenHeader(absolutePath, _limits.MaxSourcePixels);
        return UntrustedImageDecoding.DecodeFirstFrame(codec, targetBox);
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
                using var page = RenderPdfFirstPageBounded(absolutePath);
                return RenderContainedImage(page);
            }
            finally
            {
                PdfRenderSlots.Release();
            }
        }, CancellationToken.None);

        try
        {
            return await render.WaitAsync(ct);
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
    }

    /// <summary>
    /// Errors PDFium/PDFtoImage raise for a bad document (and the empty-page guard below). Anything else, such as an
    /// IO failure reading the scratch copy, is infrastructure and must propagate so the job is retried.
    /// </summary>
    private static bool IsPdfInputError(Exception ex) =>
        ex is PdfException or ArgumentException or InvalidOperationException;

    /// <summary>
    /// Rasterizes page one of a PDF with the longer side at <see cref="PdfLongSidePixels"/> pixels (aspect ratio
    /// preserved). Pages with a side above <see cref="PdfMaxPagePoints"/> points throw <see cref="PreviewSourceRejectedException"/>.
    /// Public so tests can check the intermediate raster size; the caller is responsible for byte budget and timeout,
    /// and disposes the bitmap.
    /// </summary>
    public static SKBitmap RenderPdfFirstPageBounded(string absolutePath)
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
        var page = Conversion.ToImage(pdf, page: 0, leaveOpen: true, password: null, options: options);
        page.SetImmutable();
        return page;
    }

    /// <summary>
    /// The size at which <paramref name="source"/> fits <paramref name="box"/> exactly on one side, scaling in either
    /// direction and keeping the aspect ratio: a 40x30 source fills the box, while an extreme strip such as 2400x1 is
    /// bounded by the box width (never 720000x300). Dimensions never drop below 1.
    /// </summary>
    private static SKSizeI FitWithin(SKSizeI source, SKSizeI box)
    {
        var scale = Math.Min((double)box.Width / source.Width, (double)box.Height / source.Height);
        return new SKSizeI(
            Math.Max(1, (int)Math.Round(source.Width * scale)),
            Math.Max(1, (int)Math.Round(source.Height * scale)));
    }

    private static byte[] RenderContainedImage(SKBitmap source)
    {
        using var surface = CreateCanvas();
        var size = FitWithin(source.Info.Size, new SKSizeI(ContentMaxWidth, ContentMaxHeight));
        var x = (CanvasWidth - size.Width) / 2;
        var y = 20 + (ContentMaxHeight - size.Height) / 2;
        surface.Canvas.DrawBitmap(source, SKRect.Create(x, y, size.Width, size.Height), Resampling);
        return EncodeJpeg(surface, 84);
    }

    private byte[] RenderTextPreview(string text)
    {
        using var surface = CreateCanvas();
        var canvas = surface.Canvas;
        using var fill = new SKPaint { Color = White, IsAntialias = true };
        using var stroke = new SKPaint { Color = Border, IsAntialias = true, IsStroke = true, StrokeWidth = 1 };
        var frame = SKRect.Create(20, 20, CanvasWidth - 40, CanvasHeight - 40);
        canvas.DrawRect(frame, fill);
        canvas.DrawRect(frame, stroke);

        using var font = SkiaText.CreateFont(_typefaces.Regular, 18);
        using var ink = SkiaText.CreatePaint(InkLight);
        canvas.Save();
        canvas.ClipRect(SKRect.Create(34, 36, CanvasWidth - 68, CanvasHeight - 72));
        SkiaText.DrawWrapped(canvas, NormalizeText(text), font, ink, 34, 36, CanvasWidth - 68);
        canvas.Restore();

        return EncodeJpeg(surface, 85);
    }

    private byte[] GetOrCreatePendingPreviewBytes()
    {
        if (_pendingPreviewBytes is not null)
        {
            return _pendingPreviewBytes;
        }

        lock (GenericPreviewSync)
        {
            _pendingPreviewBytes ??= RenderGenericStatusPreview(_typefaces, "Preparing preview...");
            return _pendingPreviewBytes;
        }
    }

    private byte[] GetOrCreateUnavailablePreviewBytes()
    {
        if (_unavailablePreviewBytes is not null)
        {
            return _unavailablePreviewBytes;
        }

        lock (GenericPreviewSync)
        {
            _unavailablePreviewBytes ??= RenderGenericStatusPreview(_typefaces, "Preview cannot be shown for this file type.");
            return _unavailablePreviewBytes;
        }
    }

    private static byte[] RenderGenericStatusPreview(BrandTypefaces typefaces, string message)
    {
        using var surface = CreateCanvas();
        var canvas = surface.Canvas;

        using (var gradient = new SKPaint
               {
                   Shader = SKShader.CreateLinearGradient(
                       new SKPoint(0, 0),
                       new SKPoint(CanvasWidth, CanvasHeight),
                       [Terra.WithAlpha(22), Terra.WithAlpha(0)],
                       SKShaderTileMode.Clamp)
               })
        {
            canvas.DrawRect(SKRect.Create(CanvasWidth, CanvasHeight), gradient);
        }

        var card = SKRect.Create(70, 90, CanvasWidth - 140, CanvasHeight - 180);
        using (var fill = new SKPaint { Color = White, IsAntialias = true })
        using (var stroke = new SKPaint { Color = Border, IsAntialias = true, IsStroke = true, StrokeWidth = 1 })
        {
            canvas.DrawRect(card, fill);
            canvas.DrawRect(card, stroke);
        }

        using (var titleFont = SkiaText.CreateFont(typefaces.Bold, 52))
        using (var titlePaint = SkiaText.CreatePaint(Terra))
        using (var bodyFont = SkiaText.CreateFont(typefaces.Regular, 18))
        using (var bodyPaint = SkiaText.CreatePaint(InkLight))
        {
            SkiaText.DrawWrapped(canvas, "PREVIEW", titleFont, titlePaint, CanvasWidth / 2f, 290, CanvasWidth, SKTextAlign.Center);
            SkiaText.DrawWrapped(canvas, message, bodyFont, bodyPaint, CanvasWidth / 2f, 380, CanvasWidth - 220, SKTextAlign.Center);
        }

        return EncodeJpeg(surface, 85);
    }

    private static SKSurface CreateCanvas()
    {
        var surface = SKSurface.Create(new SKImageInfo(CanvasWidth, CanvasHeight, SKColorType.Rgba8888, SKAlphaType.Premul));
        surface.Canvas.Clear(White);
        return surface;
    }

    private static byte[] EncodeJpeg(SKSurface surface, int quality)
    {
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Jpeg, quality)
            ?? throw new InvalidOperationException("JPEG encoding failed.");
        return data.ToArray();
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
