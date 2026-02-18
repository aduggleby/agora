using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Drawing;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using IOPath = System.IO.Path;

namespace Agora.Web.Services;

public sealed class OgImageGenerator
{
    private const int Width = 1200;
    private const int Height = 630;

    private static readonly Color Cream = Color.ParseHex("#FAF7F2");
    private static readonly Color Ink = Color.ParseHex("#1A1614");
    private static readonly Color InkLight = Color.ParseHex("#5C534A");
    private static readonly Color InkMuted = Color.ParseHex("#9B9189");
    private static readonly Color Terra = Color.ParseHex("#C4663A");
    private static readonly Color CardBg = Color.ParseHex("#FFFFFF");
    private static readonly Color FilePillBg = Color.ParseHex("#F5F0E8");

    private readonly FontFamily _fontFamily;
    private readonly Font _titleFont;
    private readonly Font _subtitleFont;
    private readonly Font _smallFont;
    private readonly Font _brandFont;

    public OgImageGenerator(string fontsDirectory)
    {
        var collection = new FontCollection();
        collection.Add(IOPath.Combine(fontsDirectory, "DMSans-Regular.ttf"));
        collection.Add(IOPath.Combine(fontsDirectory, "DMSans-Medium.ttf"));
        _fontFamily = collection.Add(IOPath.Combine(fontsDirectory, "DMSans-Bold.ttf"));

        _titleFont = _fontFamily.CreateFont(44, FontStyle.Bold);
        _subtitleFont = _fontFamily.CreateFont(22, FontStyle.Regular);
        _smallFont = _fontFamily.CreateFont(16, FontStyle.Regular);
        _brandFont = _fontFamily.CreateFont(18, FontStyle.Bold);
    }

    public async Task<byte[]> GenerateShareOgImageAsync(
        string? backgroundImagePath,
        string? backgroundColorHex,
        string title,
        string? subtitle,
        string fileName,
        int fileCount,
        string sizeDisplay,
        bool isExpired)
    {
        using var image = new Image<Rgba32>(Width, Height);

        if (!string.IsNullOrWhiteSpace(backgroundImagePath) && File.Exists(backgroundImagePath))
            await DrawBackgroundImageAsync(image, backgroundImagePath);
        else
            DrawGradientBackground(image, backgroundColorHex);

        DrawShareCard(image, title, subtitle, fileName, fileCount, sizeDisplay, isExpired);
        DrawBranding(image, !string.IsNullOrWhiteSpace(backgroundImagePath));

        using var ms = new MemoryStream();
        await image.SaveAsPngAsync(ms);
        return ms.ToArray();
    }

    public async Task<byte[]> GenerateDefaultOgImageAsync(string heading, string? description)
    {
        using var image = new Image<Rgba32>(Width, Height);
        DrawGradientBackground(image, null);

        // Decorative elements
        image.Mutate(ctx =>
        {
            ctx.Fill(new Color(new Rgba32(196, 102, 58, 12)), new EllipsePolygon(150, 100, 200));
            ctx.Fill(new Color(new Rgba32(196, 102, 58, 8)), new EllipsePolygon(1050, 500, 250));
        });

        // Center text
        var titleOpts = new RichTextOptions(_fontFamily.CreateFont(56, FontStyle.Bold))
        {
            Origin = new PointF(Width / 2f, Height / 2f - 30),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            WrappingLength = Width - 200
        };
        image.Mutate(ctx => ctx.DrawText(titleOpts, heading, Ink));

        if (!string.IsNullOrWhiteSpace(description))
        {
            var descOpts = new RichTextOptions(_subtitleFont)
            {
                Origin = new PointF(Width / 2f, Height / 2f + 35),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                WrappingLength = Width - 300
            };
            image.Mutate(ctx => ctx.DrawText(descOpts, description, InkLight));
        }

        var brandOpts = new RichTextOptions(_brandFont)
        {
            Origin = new PointF(Width / 2f, Height - 50),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };
        image.Mutate(ctx => ctx.DrawText(brandOpts, "Agora", Terra));

        using var ms = new MemoryStream();
        await image.SaveAsPngAsync(ms);
        return ms.ToArray();
    }

    private async Task DrawBackgroundImageAsync(Image<Rgba32> canvas, string imagePath)
    {
        try
        {
            using var bgImage = await Image.LoadAsync<Rgba32>(imagePath);
            var scale = Math.Max((float)Width / bgImage.Width, (float)Height / bgImage.Height);
            bgImage.Mutate(ctx =>
            {
                ctx.Resize((int)(bgImage.Width * scale), (int)(bgImage.Height * scale));
                var cropX = (bgImage.Width - Width) / 2;
                var cropY = (bgImage.Height - Height) / 2;
                ctx.Crop(new Rectangle(Math.Max(0, cropX), Math.Max(0, cropY), Width, Height));
                ctx.GaussianBlur(15);
            });

            canvas.Mutate(ctx =>
            {
                ctx.DrawImage(bgImage, new Point(0, 0), 1f);
                // Dark overlay
                ctx.Fill(new Color(new Rgba32(0, 0, 0, 130)), new RectangularPolygon(0, 0, Width, Height));
            });
        }
        catch
        {
            DrawGradientBackground(canvas, null);
        }
    }

    private static void DrawGradientBackground(Image<Rgba32> canvas, string? colorHex)
    {
        var baseColor = Cream;
        if (!string.IsNullOrWhiteSpace(colorHex))
        {
            try { baseColor = Color.ParseHex(colorHex); } catch { /* keep default */ }
        }

        canvas.Mutate(ctx =>
        {
            ctx.Fill(baseColor);
            var gradientBrush = new LinearGradientBrush(
                new PointF(0, 0),
                new PointF(Width, Height),
                GradientRepetitionMode.None,
                new ColorStop(0, new Color(new Rgba32(196, 102, 58, 18))),
                new ColorStop(0.5f, Color.Transparent),
                new ColorStop(1, new Color(new Rgba32(196, 102, 58, 12)))
            );
            ctx.Fill(gradientBrush, new RectangularPolygon(0, 0, Width, Height));
        });
    }

    private void DrawShareCard(Image<Rgba32> canvas, string title, string? subtitle, string fileName, int fileCount, string sizeDisplay, bool isExpired)
    {
        const int cardW = 640;
        const int cardH = 360;
        const int cardX = (Width - cardW) / 2;
        const int cardY = (Height - cardH) / 2 - 15;
        const int pad = 44;

        // Soft shadow
        canvas.Mutate(ctx =>
        {
            ctx.Fill(new Color(new Rgba32(26, 22, 20, 12)),
                new RectangularPolygon(cardX + 6, cardY + 8, cardW, cardH));
            ctx.Fill(new Color(new Rgba32(26, 22, 20, 8)),
                new RectangularPolygon(cardX + 3, cardY + 4, cardW, cardH));
        });

        // Card body
        canvas.Mutate(ctx =>
            ctx.Fill(CardBg, new RectangularPolygon(cardX, cardY, cardW, cardH)));

        // Terra accent bar at top
        canvas.Mutate(ctx =>
            ctx.Fill(Terra, new RectangularPolygon(cardX, cardY, cardW, 5)));

        float cx = cardX + pad;
        float cw = cardW - pad * 2;
        float y = cardY + pad;

        // Title
        var titleText = Truncate(title, 50);
        var titleOpts = new RichTextOptions(_titleFont)
        {
            Origin = new PointF(cx, y),
            WrappingLength = cw,
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top
        };
        canvas.Mutate(ctx => ctx.DrawText(titleOpts, titleText, Ink));
        y += TextMeasurer.MeasureSize(titleText, titleOpts).Height + 6;

        // Subtitle
        if (!string.IsNullOrWhiteSpace(subtitle))
        {
            var subOpts = new RichTextOptions(_subtitleFont)
            {
                Origin = new PointF(cx, y),
                WrappingLength = cw,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top
            };
            canvas.Mutate(ctx => ctx.DrawText(subOpts, Truncate(subtitle, 70), InkLight));
            y += TextMeasurer.MeasureSize(Truncate(subtitle, 70), subOpts).Height + 18;
        }
        else
        {
            y += 14;
        }

        // File info pill
        const float pillH = 60;
        canvas.Mutate(ctx =>
            ctx.Fill(FilePillBg, new RectangularPolygon(cx, y, cw, pillH)));

        // File icon block
        canvas.Mutate(ctx =>
            ctx.Fill(Terra, new RectangularPolygon(cx + 16, y + 15, 28, 30)));
        // Small cutout effect on icon
        canvas.Mutate(ctx =>
            ctx.Fill(FilePillBg, new RectangularPolygon(cx + 20, y + 19, 10, 8)));

        // File name
        var fnOpts = new RichTextOptions(_fontFamily.CreateFont(17, FontStyle.Bold))
        {
            Origin = new PointF(cx + 58, y + 14),
            VerticalAlignment = VerticalAlignment.Top
        };
        canvas.Mutate(ctx => ctx.DrawText(fnOpts, Truncate(fileName, 40), Ink));

        // File meta line
        var filesLabel = fileCount == 1 ? "1 file" : $"{fileCount} files";
        var metaOpts = new RichTextOptions(_smallFont)
        {
            Origin = new PointF(cx + 58, y + 37),
            VerticalAlignment = VerticalAlignment.Top
        };
        canvas.Mutate(ctx => ctx.DrawText(metaOpts, $"{filesLabel}  \u00B7  {sizeDisplay}", InkMuted));

        y += pillH + 18;

        // Button
        const float btnH = 44;
        if (isExpired)
        {
            canvas.Mutate(ctx =>
            {
                ctx.Fill(new Color(new Rgba32(246, 229, 220, 255)),
                    new RectangularPolygon(cx, y, cw, btnH));
                var opts = new RichTextOptions(_fontFamily.CreateFont(16, FontStyle.Bold))
                {
                    Origin = new PointF(cx + cw / 2f, y + btnH / 2f),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                ctx.DrawText(opts, "Link Expired", new Color(new Rgba32(122, 63, 32, 255)));
            });
        }
        else
        {
            canvas.Mutate(ctx =>
            {
                ctx.Fill(Terra, new RectangularPolygon(cx, y, cw, btnH));
                var opts = new RichTextOptions(_fontFamily.CreateFont(16, FontStyle.Bold))
                {
                    Origin = new PointF(cx + cw / 2f, y + btnH / 2f),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                ctx.DrawText(opts, "Download", Color.White);
            });
        }
    }

    private void DrawBranding(Image<Rgba32> canvas, bool hasBgImage)
    {
        var textColor = hasBgImage ? new Color(new Rgba32(255, 255, 255, 200)) : InkMuted;
        var accentColor = hasBgImage ? new Color(new Rgba32(255, 255, 255, 240)) : Terra;

        var brandOpts = new RichTextOptions(_brandFont)
        {
            Origin = new PointF(40, Height - 38),
            VerticalAlignment = VerticalAlignment.Center
        };
        canvas.Mutate(ctx => ctx.DrawText(brandOpts, "Agora", accentColor));

        var tagOpts = new RichTextOptions(_smallFont)
        {
            Origin = new PointF(100, Height - 38),
            VerticalAlignment = VerticalAlignment.Center
        };
        canvas.Mutate(ctx => ctx.DrawText(tagOpts, "Self-hosted file transfer", textColor));
    }

    private static string Truncate(string text, int max)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        return text.Length <= max ? text : text[..(max - 1)] + "\u2026";
    }
}
