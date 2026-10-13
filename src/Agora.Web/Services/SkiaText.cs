using SkiaSharp;

namespace Agora.Web.Services;

/// <summary>Word-wrapped text drawing on an <see cref="SKCanvas"/>. Fonts and paints are created per call: both are mutable.</summary>
public static class SkiaText
{
    public static SKFont CreateFont(SKTypeface typeface, float size) => new(typeface, size)
    {
        Subpixel = true,
        Edging = SKFontEdging.SubpixelAntialias
    };

    public static SKPaint CreatePaint(SKColor color) => new() { Color = color, IsAntialias = true };

    /// <summary>
    /// Greedy word wrap: explicit line breaks are kept, words are packed while they fit <paramref name="maxWidth"/>,
    /// and a single word wider than the line is broken at the last character that fits.
    /// </summary>
    public static List<string> Wrap(string text, SKFont font, float maxWidth)
    {
        var lines = new List<string>();
        foreach (var paragraph in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var current = string.Empty;
            foreach (var word in paragraph.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = current.Length == 0 ? word : current + " " + word;
                if (font.MeasureText(candidate) <= maxWidth)
                {
                    current = candidate;
                    continue;
                }

                if (current.Length > 0)
                {
                    lines.Add(current);
                    current = string.Empty;
                }

                var rest = word;
                while (rest.Length > 0 && font.MeasureText(rest) > maxWidth)
                {
                    var fits = Math.Max(1, (int)font.BreakText(rest, maxWidth));
                    lines.Add(rest[..fits]);
                    rest = rest[fits..];
                }

                current = rest;
            }

            lines.Add(current);
        }

        return lines;
    }

    /// <summary>Height of <paramref name="text"/> wrapped to <paramref name="maxWidth"/>, in lines of <see cref="SKFont.Spacing"/>.</summary>
    public static float MeasureHeight(string text, SKFont font, float maxWidth) => Wrap(text, font, maxWidth).Count * font.Spacing;

    /// <summary>
    /// Draws <paramref name="text"/> wrapped to <paramref name="maxWidth"/> with the first line's top at
    /// <paramref name="top"/>. <paramref name="x"/> is the left edge, centre or right edge depending on
    /// <paramref name="align"/>. Returns the height drawn.
    /// </summary>
    public static float DrawWrapped(SKCanvas canvas, string text, SKFont font, SKPaint paint, float x, float top, float maxWidth, SKTextAlign align = SKTextAlign.Left)
    {
        var baseline = top - font.Metrics.Ascent;
        var lines = Wrap(text, font, maxWidth);
        foreach (var line in lines)
        {
            canvas.DrawText(line, x, baseline, align, font, paint);
            baseline += font.Spacing;
        }

        return lines.Count * font.Spacing;
    }

    /// <summary>Draws one line of text with its vertical centre at <paramref name="centerY"/>.</summary>
    public static void DrawCentered(SKCanvas canvas, string text, SKFont font, SKPaint paint, float x, float centerY, SKTextAlign align = SKTextAlign.Left)
    {
        var metrics = font.Metrics;
        canvas.DrawText(text, x, centerY - (metrics.Ascent + metrics.Descent) / 2, align, font, paint);
    }
}
