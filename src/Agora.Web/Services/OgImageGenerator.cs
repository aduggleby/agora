using SkiaSharp;

namespace Agora.Web.Services;

public sealed class OgImageGenerator
{
    private const int Width = 1200;
    private const int Height = 630;

    private static readonly SKColor Cream = SKColor.Parse("#FAF7F2");
    private static readonly SKColor Ink = SKColor.Parse("#1A1614");
    private static readonly SKColor InkLight = SKColor.Parse("#5C534A");
    private static readonly SKColor InkMuted = SKColor.Parse("#9B9189");
    private static readonly SKColor Terra = SKColor.Parse("#C4663A");
    private static readonly SKColor CardBg = SKColors.White;
    private static readonly SKColor FilePillBg = SKColor.Parse("#F5F0E8");

    private static readonly SKSamplingOptions Resampling = new(SKCubicResampler.Mitchell);

    private readonly BrandTypefaces _typefaces;
    private readonly int _decodeTimeoutSeconds;

    /// <param name="fontsDirectory">Directory holding the brand fonts.</param>
    /// <param name="decodeTimeoutSeconds">
    /// Time budget for a render that decodes a background, including the wait for a raster decode slot
    /// (normally <c>Agora:Previews:TimeoutSeconds</c>).
    /// </param>
    public OgImageGenerator(string fontsDirectory, int decodeTimeoutSeconds = 30)
    {
        _typefaces = new BrandTypefaces(fontsDirectory);
        _decodeTimeoutSeconds = decodeTimeoutSeconds;
    }

    public const long MaxBackgroundBytes = 20L * 1024 * 1024;
    /// <summary>
    /// Pixel budget for share backgrounds, checked at upload and again before every decode (a 4K image is 8.3 million
    /// pixels). PNG and BMP decode at full size, so this times four bytes is what one background decode can allocate.
    /// </summary>
    public const long MaxBackgroundPixels = 16_000_000;
    public const double MaxBackgroundAspectRatio = 10;

    /// <summary>Shown when an uploaded background is refused by <see cref="IsAcceptableBackground(string)"/>.</summary>
    public const string BackgroundRefusalMessage =
        "The background image could not be read or is larger than 16 megapixels (for example 4000 x 4000 pixels).";

    /// <summary>
    /// Upload-time check of a background: the header must be a supported image within <see cref="MaxBackgroundPixels"/>
    /// (see <see cref="UntrustedImageDecoding.OpenHeader(string, long)"/>). Only the header is parsed, nothing is decoded,
    /// so this runs without a decode slot; the upload endpoints calling it are signed-in and admission-capped.
    /// </summary>
    public static bool IsAcceptableBackground(string absolutePath)
    {
        try
        {
            using var codec = UntrustedImageDecoding.OpenHeader(absolutePath, MaxBackgroundPixels);
            return true;
        }
        catch (PreviewSourceRejectedException)
        {
            return false;
        }
    }

    /// <summary>Stream variant of <see cref="IsAcceptableBackground(string)"/>; a stream that cannot seek is refused.</summary>
    public static bool IsAcceptableBackground(Stream stream)
    {
        try
        {
            using var codec = UntrustedImageDecoding.OpenHeader(stream, MaxBackgroundPixels);
            return true;
        }
        catch (PreviewSourceRejectedException)
        {
            return false;
        }
    }

    /// <summary>
    /// A rendered link-preview image. <paramref name="Cacheable"/> is false when the background was not drawn only
    /// because the decode slots or the time budget ran out; such a render must not be stored, so a later request retries.
    /// </summary>
    public sealed record OgImage(byte[] Png, bool Cacheable);

    /// <summary>
    /// Renders the share's link-preview image. A background is decoded and drawn inside one of the shared raster decode
    /// slots (<see cref="SharePreviewImageGenerator.RasterDecodeSlots"/>) under the decode time budget; when no slot
    /// frees up in time or the render runs over, the gradient is drawn instead and the result is not cacheable.
    /// Takes ownership of <paramref name="backgroundImage"/> and disposes it (possibly after this method returns, when
    /// an abandoned render is still reading it), so the caller must not dispose or touch it afterwards.
    /// </summary>
    public async Task<OgImage> GenerateShareOgImageAsync(
        Stream? backgroundImage,
        string? backgroundColorHex,
        string title,
        string? subtitle,
        string fileName,
        int fileCount,
        string sizeDisplay,
        bool isExpired,
        CancellationToken ct = default)
    {
        byte[] Render(Stream? background) =>
            RenderShareOgImage(background, backgroundColorHex, title, subtitle, fileName, fileCount, sizeDisplay, isExpired);

        if (backgroundImage is null)
        {
            return new OgImage(Render(null), Cacheable: true);
        }

        // Checked without a slot: nothing is decoded and an oversized background is skipped without being read.
        if (!backgroundImage.CanSeek || backgroundImage.Length > MaxBackgroundBytes)
        {
            await backgroundImage.DisposeAsync();
            return new OgImage(Render(null), Cacheable: true);
        }

        // Whoever claims the stream first owns it: the worker when it starts, or this method when the worker never
        // started (slot wait timed out). An abandoned worker keeps reading until it exits, so only it may dispose then.
        var claimed = 0;
        try
        {
            var png = await SharePreviewImageGenerator.WithTimeoutAsync(
                token => SharePreviewImageGenerator.RunBoundedAsync(() =>
                {
                    if (Interlocked.Exchange(ref claimed, 1) != 0)
                    {
                        return Array.Empty<byte>();
                    }

                    using (backgroundImage)
                    {
                        return Render(backgroundImage);
                    }
                }, token),
                _decodeTimeoutSeconds,
                ct);
            return new OgImage(png, Cacheable: true);
        }
        catch (PreviewSourceRejectedException)
        {
            // Only the time budget surfaces here; undecodable or oversized backgrounds are skipped inside the render.
            ReleaseUnclaimed(backgroundImage, ref claimed);
            return new OgImage(Render(null), Cacheable: false);
        }
        catch
        {
            ReleaseUnclaimed(backgroundImage, ref claimed);
            throw;
        }
    }

    private static void ReleaseUnclaimed(Stream stream, ref int claimed)
    {
        if (Interlocked.Exchange(ref claimed, 1) == 0)
        {
            stream.Dispose();
        }
    }

    private byte[] RenderShareOgImage(
        Stream? backgroundImage,
        string? backgroundColorHex,
        string title,
        string? subtitle,
        string fileName,
        int fileCount,
        string sizeDisplay,
        bool isExpired)
    {
        using var surface = SKSurface.Create(new SKImageInfo(Width, Height, SKColorType.Rgba8888, SKAlphaType.Premul));
        var canvas = surface.Canvas;

        var hasBackground = backgroundImage is not null && DrawBackgroundImage(canvas, backgroundImage);
        if (!hasBackground)
            DrawGradientBackground(canvas, backgroundColorHex);

        DrawShareCard(canvas, title, subtitle, fileName, fileCount, sizeDisplay, isExpired);
        DrawBranding(canvas, hasBackground);

        return EncodePng(surface);
    }

    public Task<byte[]> GenerateDefaultOgImageAsync(string heading, string? description)
    {
        using var surface = SKSurface.Create(new SKImageInfo(Width, Height, SKColorType.Rgba8888, SKAlphaType.Premul));
        var canvas = surface.Canvas;
        DrawGradientBackground(canvas, null);

        // Decorative elements
        using (var paint = new SKPaint { Color = Terra.WithAlpha(12), IsAntialias = true })
        {
            canvas.DrawCircle(150, 100, 200, paint);
            paint.Color = Terra.WithAlpha(8);
            canvas.DrawCircle(1050, 500, 250, paint);
        }

        // Center text
        using (var font = SkiaText.CreateFont(_typefaces.Bold, 56))
        using (var paint = SkiaText.CreatePaint(Ink))
        {
            var height = SkiaText.MeasureHeight(heading, font, Width - 200);
            SkiaText.DrawWrapped(canvas, heading, font, paint, Width / 2f, Height / 2f - 30 - height / 2, Width - 200, SKTextAlign.Center);
        }

        if (!string.IsNullOrWhiteSpace(description))
        {
            using var font = SkiaText.CreateFont(_typefaces.Regular, 22);
            using var paint = SkiaText.CreatePaint(InkLight);
            var height = SkiaText.MeasureHeight(description, font, Width - 300);
            SkiaText.DrawWrapped(canvas, description, font, paint, Width / 2f, Height / 2f + 35 - height / 2, Width - 300, SKTextAlign.Center);
        }

        using (var font = SkiaText.CreateFont(_typefaces.Bold, 18))
        using (var paint = SkiaText.CreatePaint(Terra))
        {
            SkiaText.DrawCentered(canvas, "Agora", font, paint, Width / 2f, Height - 50, SKTextAlign.Center);
        }

        return Task.FromResult(EncodePng(surface));
    }

    /// <summary>
    /// Draws the uploaded background cover-cropped and blurred straight into the canvas (no cover-sized intermediate:
    /// the decode is downscaled towards 1200x630 where the format allows and the crop happens in the draw).
    /// Backgrounds above <see cref="MaxBackgroundBytes"/>, <see cref="MaxBackgroundPixels"/> or
    /// <see cref="MaxBackgroundAspectRatio"/> are skipped, as are undecodable ones. Returns false when nothing was drawn.
    /// </summary>
    private static bool DrawBackgroundImage(SKCanvas canvas, Stream imageStream)
    {
        try
        {
            if (!imageStream.CanSeek || imageStream.Length > MaxBackgroundBytes)
            {
                return false;
            }

            using var codec = UntrustedImageDecoding.OpenHeader(imageStream, MaxBackgroundPixels);
            var info = codec.Info;

            // Covering 1200x630 with an extreme strip (e.g. 400x1) would blow the strip up to thousands of pixels.
            var aspect = (double)Math.Max(info.Width, info.Height) / Math.Min(info.Width, info.Height);
            if (aspect > MaxBackgroundAspectRatio)
            {
                return false;
            }

            using var bgImage = UntrustedImageDecoding.DecodeFirstFrame(codec, new SKSizeI(Width, Height), cover: true);

            // Centre crop of the source at the canvas aspect ratio.
            var scale = Math.Max((float)Width / bgImage.Width, (float)Height / bgImage.Height);
            var cropWidth = Width / scale;
            var cropHeight = Height / scale;
            var source = SKRect.Create((bgImage.Width - cropWidth) / 2, (bgImage.Height - cropHeight) / 2, cropWidth, cropHeight);

            using (var paint = new SKPaint { ImageFilter = SKImageFilter.CreateBlur(15, 15, SKShaderTileMode.Clamp) })
            {
                canvas.DrawBitmap(bgImage, source, SKRect.Create(Width, Height), Resampling, paint);
            }

            // Dark overlay
            using (var overlay = new SKPaint { Color = SKColors.Black.WithAlpha(130) })
            {
                canvas.DrawRect(SKRect.Create(Width, Height), overlay);
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void DrawGradientBackground(SKCanvas canvas, string? colorHex)
    {
        var baseColor = Cream;
        if (!string.IsNullOrWhiteSpace(colorHex) && SKColor.TryParse(colorHex, out var parsed))
        {
            baseColor = parsed;
        }

        canvas.Clear(baseColor);
        using var gradient = new SKPaint
        {
            Shader = SKShader.CreateLinearGradient(
                new SKPoint(0, 0),
                new SKPoint(Width, Height),
                [Terra.WithAlpha(18), Terra.WithAlpha(0), Terra.WithAlpha(12)],
                [0f, 0.5f, 1f],
                SKShaderTileMode.Clamp)
        };
        canvas.DrawRect(SKRect.Create(Width, Height), gradient);
    }

    private void DrawShareCard(SKCanvas canvas, string title, string? subtitle, string fileName, int fileCount, string sizeDisplay, bool isExpired)
    {
        const int cardW = 640;
        const int cardH = 360;
        const int cardX = (Width - cardW) / 2;
        const int cardY = (Height - cardH) / 2 - 15;
        const int pad = 44;
        const float cardRadius = 16;
        const float panelRadius = 8;

        using var fill = new SKPaint { IsAntialias = true };

        // Soft shadow
        fill.Color = Ink.WithAlpha(12);
        canvas.DrawRoundRect(SKRect.Create(cardX + 6, cardY + 8, cardW, cardH), cardRadius, cardRadius, fill);
        fill.Color = Ink.WithAlpha(8);
        canvas.DrawRoundRect(SKRect.Create(cardX + 3, cardY + 4, cardW, cardH), cardRadius, cardRadius, fill);

        // Card body with a terra accent bar at the top (clipped to the rounded card)
        var card = SKRect.Create(cardX, cardY, cardW, cardH);
        fill.Color = CardBg;
        canvas.DrawRoundRect(card, cardRadius, cardRadius, fill);
        canvas.Save();
        canvas.ClipRoundRect(new SKRoundRect(card, cardRadius), antialias: true);
        fill.Color = Terra;
        canvas.DrawRect(SKRect.Create(cardX, cardY, cardW, 5), fill);
        canvas.Restore();

        float cx = cardX + pad;
        float cw = cardW - pad * 2;
        float y = cardY + pad;

        // Title
        using (var font = SkiaText.CreateFont(_typefaces.Bold, 35))
        using (var paint = SkiaText.CreatePaint(Ink))
        {
            y += SkiaText.DrawWrapped(canvas, Truncate(title, 50), font, paint, cx, y, cw) + 6;
        }

        // Subtitle
        if (!string.IsNullOrWhiteSpace(subtitle))
        {
            using var font = SkiaText.CreateFont(_typefaces.Regular, 22);
            using var paint = SkiaText.CreatePaint(InkLight);
            y += SkiaText.DrawWrapped(canvas, Truncate(subtitle, 70), font, paint, cx, y, cw) + 18;
        }
        else
        {
            y += 14;
        }

        // File info pill
        const float pillH = 60;
        fill.Color = FilePillBg;
        canvas.DrawRoundRect(SKRect.Create(cx, y, cw, pillH), panelRadius, panelRadius, fill);

        // File icon block with a small cutout effect
        fill.Color = Terra;
        canvas.DrawRoundRect(SKRect.Create(cx + 16, y + 15, 28, 30), 3, 3, fill);
        fill.Color = FilePillBg;
        canvas.DrawRect(SKRect.Create(cx + 20, y + 19, 10, 8), fill);

        // File name
        using (var font = SkiaText.CreateFont(_typefaces.Bold, 17))
        using (var paint = SkiaText.CreatePaint(Ink))
        {
            canvas.DrawText(Truncate(fileName, 40), cx + 58, y + 14 - font.Metrics.Ascent, SKTextAlign.Left, font, paint);
        }

        // File meta line
        var filesLabel = fileCount == 1 ? "1 file" : $"{fileCount} files";
        using (var font = SkiaText.CreateFont(_typefaces.Regular, 16))
        using (var paint = SkiaText.CreatePaint(InkMuted))
        {
            canvas.DrawText($"{filesLabel}  ·  {sizeDisplay}", cx + 58, y + 37 - font.Metrics.Ascent, SKTextAlign.Left, font, paint);
        }

        y += pillH + 18;

        // Button
        const float btnH = 44;
        var button = SKRect.Create(cx, y, cw, btnH);
        fill.Color = isExpired ? new SKColor(246, 229, 220) : Terra;
        canvas.DrawRoundRect(button, panelRadius, panelRadius, fill);
        using (var font = SkiaText.CreateFont(_typefaces.Bold, 16))
        using (var paint = SkiaText.CreatePaint(isExpired ? new SKColor(122, 63, 32) : SKColors.White))
        {
            SkiaText.DrawCentered(canvas, isExpired ? "Link Expired" : "Download", font, paint, cx + cw / 2f, y + btnH / 2f, SKTextAlign.Center);
        }
    }

    private void DrawBranding(SKCanvas canvas, bool hasBgImage)
    {
        var textColor = hasBgImage ? SKColors.White.WithAlpha(200) : InkMuted;
        var accentColor = hasBgImage ? SKColors.White.WithAlpha(240) : Terra;

        using (var font = SkiaText.CreateFont(_typefaces.Bold, 18))
        using (var paint = SkiaText.CreatePaint(accentColor))
        {
            SkiaText.DrawCentered(canvas, "Agora", font, paint, 40, Height - 38);
        }

        using (var font = SkiaText.CreateFont(_typefaces.Regular, 16))
        using (var paint = SkiaText.CreatePaint(textColor))
        {
            SkiaText.DrawCentered(canvas, "Self hosted secure file transfer", font, paint, 100, Height - 38);
        }
    }

    private static byte[] EncodePng(SKSurface surface)
    {
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 100)
            ?? throw new InvalidOperationException("PNG encoding failed.");
        return data.ToArray();
    }

    private static string Truncate(string text, int max)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        return text.Length <= max ? text : text[..(max - 1)] + "…";
    }
}
