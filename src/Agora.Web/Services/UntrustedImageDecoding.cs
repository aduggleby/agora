using System.Buffers.Binary;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Formats.Bmp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.Formats.Webp;
using SixLabors.ImageSharp.Memory;

namespace Agora.Web.Services;

/// <summary>
/// ImageSharp configuration for decoding user-uploaded images (previews, thumbnails, link-preview backgrounds).
/// Only PNG, JPEG, WEBP and BMP are registered: ImageSharp sniffs the format from the bytes, so without this a
/// "photo.png" holding a TIFF would still reach the TIFF decoder. GIF is left out on purpose (frames with disposal
/// method 3 allocate an extra full canvas regardless of <see cref="DecoderOptions.MaxFrames"/>); GIF uploads are
/// still served inline, they just get no generated preview. Metadata (EXIF, ICC, XMP) is never parsed; nothing in
/// Agora reads it.
/// </summary>
public static class UntrustedImageDecoding
{
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private const int MaxPngScanChunks = 4096;

    /// <summary>
    /// Creates a configuration with the restricted decoder set and a memory allocator whose single-buffer ceiling is
    /// four Rgba32 frames at <paramref name="maxPixels"/> (the budget itself must be enforced before decoding; this
    /// only bounds a decoder that misbehaves past its header).
    /// </summary>
    public static Configuration CreateConfiguration(long maxPixels)
    {
        var configuration = new Configuration(
            new PngConfigurationModule(),
            new JpegConfigurationModule(),
            new WebpConfigurationModule(),
            new BmpConfigurationModule());

        var budgetMegabytes = maxPixels * 4 / (1024 * 1024) * 4 + 64;
        configuration.MemoryAllocator = MemoryAllocator.Create(new MemoryAllocatorOptions
        {
            AllocationLimitMegabytes = (int)Math.Clamp(budgetMegabytes, 256, int.MaxValue)
        });
        return configuration;
    }

    /// <summary>Decoder options for one frame of an untrusted image, optionally scaled down during decoding.</summary>
    public static DecoderOptions CreateDecoderOptions(Configuration configuration, Size? targetSize = null) => new()
    {
        Configuration = configuration,
        MaxFrames = 1,
        SkipMetadata = true,
        TargetSize = targetSize
    };

    /// <summary>
    /// Pre-check for PNG sources, run before <c>Image.IdentifyAsync</c>: Identify reports the last IHDR it sees while
    /// the decoder allocates from the first, so a "12000x12000 IHDR, empty IDAT, 1x1 IHDR" file would pass a budget
    /// check based on Identify alone. Reads the first chunk (which must be an IHDR) and scans, bounded, up to the first
    /// IEND for a second IHDR. Returns null when the stream is not a PNG or the header is acceptable, otherwise the
    /// reason to reject it (sizes only, never content). The stream is read from its current position. The scan runs
    /// through IDAT chunks to IEND (a second IHDR typically follows the image data) and gives up, accepting, after
    /// <see cref="MaxPngScanChunks"/> chunks: the first-IHDR check is the one that bounds the allocation.
    /// </summary>
    public static string? RejectPngHeader(Stream stream, long maxPixels)
    {
        Span<byte> buffer = stackalloc byte[8];
        Span<byte> ihdr = stackalloc byte[13];
        if (!TryReadExactly(stream, buffer) || !buffer.SequenceEqual(PngSignature))
        {
            return null;
        }

        for (var chunkIndex = 0; chunkIndex < MaxPngScanChunks; chunkIndex++)
        {
            if (!TryReadExactly(stream, buffer))
            {
                // Truncated: the first chunk is mandatory, anything later is for the decoder to refuse.
                return chunkIndex == 0 ? "PNG has no IHDR chunk" : null;
            }

            var length = BinaryPrimitives.ReadUInt32BigEndian(buffer[..4]);
            var isIhdr = buffer[4..].SequenceEqual("IHDR"u8);
            if (chunkIndex == 0)
            {
                if (!isIhdr || length != 13)
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
                    return null;
                }

                continue;
            }

            if (isIhdr)
            {
                return "PNG declares a second IHDR chunk";
            }

            if (buffer[4..].SequenceEqual("IEND"u8))
            {
                return null;
            }

            if (length > int.MaxValue || !TrySkip(stream, (long)length + 4))
            {
                return null;
            }
        }

        return null;
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
