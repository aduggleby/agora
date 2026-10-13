using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using SkiaSharp;

namespace Agora.Application.Tests;

/// <summary>Crafts and inspects test images with SkiaSharp (the library under test), plus a hand-built GIF Skia cannot encode.</summary>
internal static class ImageCrafting
{
    /// <summary>A solid-colour image of the given size, encoded as PNG unless another format is requested.</summary>
    public static byte[] Solid(int width, int height, SKColor color, SKEncodedImageFormat format = SKEncodedImageFormat.Png)
    {
        using var bitmap = new SKBitmap(new SKImageInfo(width, height, SKColorType.Rgba8888, SKAlphaType.Premul));
        bitmap.Erase(color);
        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(format, 100) ?? throw new InvalidOperationException($"Skia cannot encode {format}");
        return data.ToArray();
    }

    /// <summary>
    /// A GIF89a whose logical screen is <paramref name="width"/> x <paramref name="height"/> with <paramref name="frames"/>
    /// one-pixel frames, each with disposal method 3 (restore to previous), the mode that keeps an extra full canvas
    /// alive while decoding. Skia opens it (format Gif, frame count as given) but Agora must refuse it from the header.
    /// </summary>
    public static byte[] Gif(int width, int height, int frames = 2)
    {
        using var output = new MemoryStream();
        output.Write("GIF89a"u8);
        output.Write([(byte)(width & 0xFF), (byte)(width >> 8), (byte)(height & 0xFF), (byte)(height >> 8)]);
        output.Write([0x80, 0x00, 0x00]);                 // global colour table with 2 entries, background 0, no aspect
        output.Write([0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]); // black, white
        for (var i = 0; i < frames; i++)
        {
            output.Write([0x21, 0xF9, 0x04, 0x0C, 0x0A, 0x00, 0x00, 0x00]); // graphic control: disposal 3, 100 ms
            output.Write([0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]); // 1x1 image at 0,0
            output.Write([0x02, 0x02, 0x44, 0x01, 0x00]);                   // LZW: clear, colour 0, end
        }

        output.WriteByte(0x3B);
        return output.ToArray();
    }

    /// <summary>
    /// A valid 1x1 PNG followed by <paramref name="count"/> zTXt chunks, each holding <paramref name="inflatedBytes"/>
    /// of zeros deflated to a few KB: the shape libpng inflates and keeps while reading the header.
    /// </summary>
    public static byte[] PngWithCompressedTextChunks(int count, int inflatedBytes = 4 * 1024 * 1024)
    {
        var text = new byte[] { (byte)'k', 0, 0 }.Concat(Deflate(new byte[inflatedBytes])).ToArray();
        var chunks = new List<(string, byte[])> { ("IHDR", PngCrafting.Ihdr(1, 1)), ("IDAT", OnePixelIdat()) };
        for (var i = 0; i < count; i++)
        {
            chunks.Add(("zTXt", text));
        }

        chunks.Add(("IEND", []));
        return PngCrafting.Craft([.. chunks]);
    }

    /// <summary>A valid 1x1 PNG with the given extra chunks between IDAT and IEND.</summary>
    public static byte[] PngWithChunks(params (string Type, byte[] Data)[] extra) =>
        PngCrafting.Craft([("IHDR", PngCrafting.Ihdr(1, 1)), ("IDAT", OnePixelIdat()), .. extra, ("IEND", [])]);

    public static byte[] Itxt(string keyword, bool compressed, string text) =>
        [.. Encoding.ASCII.GetBytes(keyword), 0, (byte)(compressed ? 1 : 0), 0, 0, 0, .. Encoding.UTF8.GetBytes(text)];

    /// <summary>A Skia-encoded JPEG with an APP1 segment of <paramref name="appBytes"/> inserted after SOI.</summary>
    public static byte[] JpegWithAppSegment(int width, int height, SKColor color, int appBytes)
    {
        var jpeg = Solid(width, height, color, SKEncodedImageFormat.Jpeg);
        var segment = new byte[appBytes + 4];
        segment[0] = 0xFF;
        segment[1] = 0xE1;
        BinaryPrimitives.WriteUInt16BigEndian(segment.AsSpan(2), (ushort)(appBytes + 2));
        Encoding.ASCII.GetBytes("Agora\0", segment.AsSpan(4));
        return [.. jpeg[..2], .. segment, .. jpeg[2..]];
    }

    /// <summary>
    /// An animated WebP (VP8X + ANIM + two ANMF frames) built around two Skia-encoded still frames, so the frames
    /// decode with the real codec while the container is the one Skia cannot write itself.
    /// </summary>
    public static byte[] AnimatedWebp(int width, int height, SKColor first, SKColor second)
    {
        using var body = new MemoryStream();
        body.Write("WEBP"u8);
        WriteRiffChunk(body, "VP8X", [0x02, 0, 0, 0, .. Uint24(width - 1), .. Uint24(height - 1)]);
        WriteRiffChunk(body, "ANIM", [0, 0, 0, 0, 0, 0]);
        foreach (var color in new[] { first, second })
        {
            var frame = WebpFrameChunks(Solid(width, height, color, SKEncodedImageFormat.Webp));
            WriteRiffChunk(body, "ANMF", [.. Uint24(0), .. Uint24(0), .. Uint24(width - 1), .. Uint24(height - 1), .. Uint24(100), 0, .. frame]);
        }

        using var output = new MemoryStream();
        output.Write("RIFF"u8);
        var size = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(size, (uint)body.Length);
        output.Write(size);
        body.WriteTo(output);
        return output.ToArray();
    }

    /// <summary>The bitstream chunks (ALPH/VP8/VP8L) of a still WebP, header and VP8X stripped.</summary>
    private static byte[] WebpFrameChunks(byte[] webp)
    {
        using var output = new MemoryStream();
        var offset = 12;
        while (offset + 8 <= webp.Length)
        {
            var fourcc = Encoding.ASCII.GetString(webp, offset, 4);
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(webp.AsSpan(offset + 4));
            var padded = length + (length & 1);
            if (fourcc is "ALPH" or "VP8 " or "VP8L")
            {
                output.Write(webp, offset, Math.Min(8 + padded, webp.Length - offset));
            }

            offset += 8 + padded;
        }

        return output.ToArray();
    }

    private static void WriteRiffChunk(Stream output, string fourcc, byte[] data)
    {
        output.Write(Encoding.ASCII.GetBytes(fourcc));
        var length = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)data.Length);
        output.Write(length);
        output.Write(data);
        if ((data.Length & 1) == 1)
        {
            output.WriteByte(0);
        }
    }

    private static byte[] Uint24(int value) => [(byte)value, (byte)(value >> 8), (byte)(value >> 16)];

    private static byte[] OnePixelIdat() => Deflate([0, 200, 100, 50, 255]);

    private static byte[] Deflate(byte[] raw)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(raw);
        }

        return output.ToArray();
    }

    public static (int Width, int Height) Dimensions(byte[] encoded)
    {
        using var codec = SKCodec.Create(new MemoryStream(encoded)) ?? throw new InvalidOperationException("not a decodable image");
        return (codec.Info.Width, codec.Info.Height);
    }

    public static SKColor Pixel(byte[] encoded, int x, int y)
    {
        using var bitmap = SKBitmap.Decode(encoded) ?? throw new InvalidOperationException("not a decodable image");
        return bitmap.GetPixel(x, y);
    }
}
