using System.Buffers.Binary;
using SkiaSharp;

namespace Agora.Web.Services;

/// <summary>
/// The single place where user-uploaded images (previews, thumbnails, link-preview backgrounds) are opened. SkiaSharp
/// sniffs the format from the bytes, so the extension is never trusted: only PNG, JPEG, WEBP and BMP are accepted,
/// decided from the codec header before any pixel is decoded. GIF is refused on purpose (frames with disposal method
/// 3 keep an extra full canvas alive; GIF uploads are still served inline, they just get no generated preview), as is
/// everything else Skia can open (ICO, WBMP, ...).
///
/// Memory: SkiaSharp has no allocator cap, so the bound is the caller's pixel budget applied to the header dimensions
/// plus decode-time downscaling where the codec supports it (JPEG in 1/8 steps, WEBP freely; PNG and BMP always decode
/// at their full size, so their ceiling is the pixel budget times four bytes). Only the first frame of an animated
/// source is decoded. Skia parses ICC and EXIF headers while opening the codec; neither is applied (no colour
/// conversion, no auto-orientation), which is as close to "skip metadata" as the library allows.
///
/// Nothing reaches the native codec without a check of our own first: the magic bytes must be one of the four formats
/// (unknown bytes are refused without native parsing), and PNGs get a chunk pre-scan (<see cref="RejectPngHeader"/>)
/// because libpng inflates and keeps compressed ancillary chunks (zTXt, compressed iTXt, iCCP) while the header is
/// read, so a 400 KB 1x1 PNG can cost hundreds of megabytes before a pixel is decoded.
/// </summary>
public static class UntrustedImageDecoding
{
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private const int MaxPngScanChunks = 4096;

    /// <summary>Total bytes of ancillary (non-critical) PNG chunks allowed before IEND; text and EXIF fit easily.</summary>
    public const int MaxPngAncillaryBytes = 64 * 1024;

    /// <summary>Longest prefix of the file needed to recognise one of the allowed formats.</summary>
    private const int MagicLength = 12;

    /// <summary>
    /// Opens the header of an image file and checks it against the budget: the format must be one of the allowed
    /// four, the declared size must be within <paramref name="maxPixels"/>. Nothing is decoded yet. Throws
    /// <see cref="PreviewSourceRejectedException"/> (sizes and format names only, never content) when the source is
    /// refused. The caller disposes the codec.
    /// </summary>
    public static SKCodec OpenHeader(string absolutePath, long maxPixels)
    {
        SKEncodedImageFormat format;
        using (var header = File.OpenRead(absolutePath))
        {
            format = SniffFormat(header);
            header.Position = 0;
            if (RejectPngHeader(header, maxPixels) is { } reason)
            {
                throw new PreviewSourceRejectedException(reason);
            }
        }

        var codec = SKCodec.Create(absolutePath, out var result);
        return CheckHeader(codec, result, format, maxPixels);
    }

    /// <summary>
    /// Stream variant of <see cref="OpenHeader(string, long)"/>. The stream must be seekable; the codec reads from it
    /// for as long as the codec lives, so the caller must not touch the stream until the codec is disposed.
    /// </summary>
    public static SKCodec OpenHeader(Stream stream, long maxPixels)
    {
        if (!stream.CanSeek)
        {
            throw new PreviewSourceRejectedException("source stream is not seekable");
        }

        stream.Position = 0;
        var format = SniffFormat(stream);
        stream.Position = 0;
        if (RejectPngHeader(stream, maxPixels) is { } reason)
        {
            throw new PreviewSourceRejectedException(reason);
        }

        stream.Position = 0;
        var codec = SKCodec.Create(stream, out var result);
        return CheckHeader(codec, result, format, maxPixels);
    }

    /// <summary>
    /// Recognises PNG, JPEG, WEBP and BMP from the first bytes, read from the stream's current position. Anything else
    /// (including GIF, which Skia could open) throws <see cref="PreviewSourceRejectedException"/>.
    /// </summary>
    public static SKEncodedImageFormat SniffFormat(Stream stream)
    {
        Span<byte> magic = stackalloc byte[MagicLength];
        var read = 0;
        while (read < magic.Length)
        {
            var count = stream.Read(magic[read..]);
            if (count <= 0)
            {
                break;
            }

            read += count;
        }

        var head = magic[..read];
        if (head.Length >= 8 && head[..8].SequenceEqual(PngSignature))
        {
            return SKEncodedImageFormat.Png;
        }

        if (head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF)
        {
            return SKEncodedImageFormat.Jpeg;
        }

        if (head.Length >= 12 && head[..4].SequenceEqual("RIFF"u8) && head[8..12].SequenceEqual("WEBP"u8))
        {
            return SKEncodedImageFormat.Webp;
        }

        if (head.Length >= 2 && head[0] == (byte)'B' && head[1] == (byte)'M')
        {
            return SKEncodedImageFormat.Bmp;
        }

        if (head.Length >= 6 && head[..3].SequenceEqual("GIF"u8))
        {
            throw new PreviewSourceRejectedException("source is not a decodable image (Gif is not an enabled format)");
        }

        throw new PreviewSourceRejectedException("source is not a decodable image (unknown format)");
    }

    private static SKCodec CheckHeader(SKCodec? codec, SKCodecResult result, SKEncodedImageFormat sniffed, long maxPixels)
    {
        if (codec is null)
        {
            throw new PreviewSourceRejectedException($"source is not a decodable image ({result})");
        }

        try
        {
            var format = codec.EncodedFormat;
            if (format != sniffed)
            {
                throw new PreviewSourceRejectedException($"source is not a decodable image (header says {sniffed}, codec says {format})");
            }

            var info = codec.Info;
            if (info.Width <= 0 || info.Height <= 0)
            {
                throw new PreviewSourceRejectedException($"source header declares an invalid size {info.Width}x{info.Height}");
            }

            var pixels = (long)info.Width * info.Height;
            if (pixels > maxPixels)
            {
                throw new PreviewSourceRejectedException(
                    $"source is {info.Width}x{info.Height} ({pixels} pixels), above the {maxPixels} pixel budget");
            }

            return codec;
        }
        catch
        {
            codec.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Decodes the first frame of a checked codec as premultiplied RGBA with no colour space, downscaled during
    /// decoding where the codec supports it so that the result covers <paramref name="targetBox"/> (cover) or fits
    /// inside it (fit). A source smaller than the box is decoded at its own size; the final scale happens when the
    /// bitmap is drawn. Truncated input decodes as far as it goes (missing rows stay transparent); any other decoder
    /// error is a <see cref="PreviewSourceRejectedException"/>.
    /// </summary>
    public static SKBitmap DecodeFirstFrame(SKCodec codec, SKSizeI targetBox, bool cover = false)
    {
        var source = codec.Info;
        var scaleX = (float)targetBox.Width / source.Width;
        var scaleY = (float)targetBox.Height / source.Height;
        var scale = cover ? Math.Max(scaleX, scaleY) : Math.Min(scaleX, scaleY);

        var size = source.Size;
        if (scale < 1)
        {
            // JPEG rounds to the nearest 1/8 (so 0.5 could become 7/16); nudge up so the decode is never below the box.
            size = codec.GetScaledDimensions(Math.Min(1f, scale + 0.0625f));
        }

        var info = new SKImageInfo(Math.Max(1, size.Width), Math.Max(1, size.Height), SKColorType.Rgba8888, SKAlphaType.Premul);
        var bitmap = new SKBitmap(info);
        try
        {
            var result = codec.GetPixels(info, bitmap.GetPixels());
            if (result is not (SKCodecResult.Success or SKCodecResult.IncompleteInput))
            {
                throw new PreviewSourceRejectedException($"source is not a decodable image ({result})");
            }

            // Immutable bitmaps are drawn by reference; a mutable one is copied in full by every DrawBitmap.
            bitmap.SetImmutable();
            return bitmap;
        }
        catch
        {
            bitmap.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Pre-check for PNG sources, run before the codec opens the file. Reads the first chunk (which must be an IHDR)
    /// and checks its size against <paramref name="maxPixels"/> (Skia allocates from this IHDR; a "12000x12000 IHDR,
    /// empty IDAT, 1x1 IHDR" file is refused as malformed), then walks every chunk up to IEND and refuses: a second
    /// IHDR, compressed ancillary chunks (zTXt, iTXt with its compression flag set, a second iCCP: libpng inflates and
    /// keeps all of them while reading the header, up to 8 MB each), more than <see cref="MaxPngAncillaryBytes"/> of
    /// ancillary chunk data in total, chunks running past the end of the stream, and files with more than
    /// <see cref="MaxPngScanChunks"/> chunks before IEND. One iCCP chunk is allowed because common exporters embed a
    /// colour profile; libpng accepts only the first and caps its inflated size.
    /// Returns null when the stream is not a PNG or passes, otherwise the reason to reject it (sizes and chunk names
    /// only, never content). The stream is read from its current position; every limit fails closed.
    /// </summary>
    public static string? RejectPngHeader(Stream stream, long maxPixels)
    {
        Span<byte> buffer = stackalloc byte[8];
        Span<byte> ihdr = stackalloc byte[13];
        Span<byte> keyword = stackalloc byte[82];
        if (!TryReadExactly(stream, buffer) || !buffer.SequenceEqual(PngSignature))
        {
            return null;
        }

        long ancillaryBytes = 0;
        var sawIccp = false;
        for (var chunkIndex = 0; chunkIndex < MaxPngScanChunks; chunkIndex++)
        {
            if (!TryReadExactly(stream, buffer))
            {
                return chunkIndex == 0 ? "PNG has no IHDR chunk" : "PNG ends before its IEND chunk";
            }

            var length = BinaryPrimitives.ReadUInt32BigEndian(buffer[..4]);
            if (length > int.MaxValue)
            {
                return "PNG declares an invalid chunk length";
            }

            var type = buffer[4..];
            if (chunkIndex == 0)
            {
                if (!type.SequenceEqual("IHDR"u8) || length != 13)
                {
                    return "PNG does not start with an IHDR chunk";
                }

                if (!TryReadExactly(stream, ihdr))
                {
                    return "PNG IHDR chunk is truncated";
                }

                var width = BinaryPrimitives.ReadUInt32BigEndian(ihdr[..4]);
                var height = BinaryPrimitives.ReadUInt32BigEndian(ihdr[4..8]);
                if (width == 0 || height == 0 || width > int.MaxValue || height > int.MaxValue)
                {
                    return $"PNG header declares an invalid size {width}x{height}";
                }

                var pixels = (long)width * height;
                if (pixels > maxPixels)
                {
                    return $"PNG header declares {width}x{height} ({pixels} pixels), above the {maxPixels} pixel budget";
                }

                if (!TrySkip(stream, 4))
                {
                    return "PNG IHDR chunk is truncated";
                }

                continue;
            }

            if (type.SequenceEqual("IHDR"u8))
            {
                return "PNG declares a second IHDR chunk";
            }

            if (type.SequenceEqual("IEND"u8))
            {
                return null;
            }

            var consumed = 0;
            var isAncillary = (type[0] & 0x20) != 0;
            if (isAncillary)
            {
                if (type.SequenceEqual("zTXt"u8))
                {
                    return "PNG contains a compressed zTXt chunk";
                }

                if (type.SequenceEqual("iCCP"u8))
                {
                    if (sawIccp)
                    {
                        return "PNG contains a second iCCP chunk";
                    }

                    sawIccp = true;
                }

                if (type.SequenceEqual("iTXt"u8))
                {
                    // keyword (1-79 bytes), null, compression flag, compression method, ...
                    var probe = keyword[..(int)Math.Min(length, (uint)keyword.Length)];
                    if (!TryReadExactly(stream, probe))
                    {
                        return "PNG iTXt chunk is truncated";
                    }

                    consumed = probe.Length;
                    var terminator = probe.IndexOf((byte)0);
                    if (terminator < 0 || terminator + 1 >= probe.Length)
                    {
                        return "PNG contains a malformed iTXt chunk";
                    }

                    if (probe[terminator + 1] != 0)
                    {
                        return "PNG contains a compressed iTXt chunk";
                    }
                }

                ancillaryBytes += length;
                if (ancillaryBytes > MaxPngAncillaryBytes)
                {
                    return $"PNG carries more than {MaxPngAncillaryBytes} bytes of ancillary chunks";
                }
            }

            if (!TrySkip(stream, (long)length - consumed + 4))
            {
                return "PNG chunk runs past the end of the file";
            }
        }

        return $"PNG has more than {MaxPngScanChunks} chunks before IEND";
    }

    private static bool TryReadExactly(Stream stream, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);
            if (read <= 0)
            {
                return false;
            }

            total += read;
        }

        return true;
    }

    private static bool TrySkip(Stream stream, long count)
    {
        if (!stream.CanSeek || stream.Position + count > stream.Length)
        {
            return false;
        }

        stream.Seek(count, SeekOrigin.Current);
        return true;
    }
}
