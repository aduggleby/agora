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

    public OgImageGenerator(string fontsDirectory)
    {
        _typefaces = new BrandTypefaces(fontsDirectory);
    }

    public const long MaxBackgroundBytes = 20L * 1024 * 1024;
    public const long MaxBackgroundPixels = 40_000_000;
    public const double MaxBackgroundAspectRatio = 10;

    public Task<byte[]> GenerateShareOgImageAsync(
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

        return Task.FromResult(EncodePng(surface));
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
