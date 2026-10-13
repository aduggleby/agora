using System.Buffers.Binary;
using System.Text;

namespace Agora.Application.Tests;

/// <summary>Builds structurally valid PNG byte streams (correct chunk CRCs) with arbitrary chunk sequences.</summary>
internal static class PngCrafting
{
    public static readonly byte[] Signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>PNG signature + IHDR declaring the given size + IEND, with no pixel data.</summary>
    public static byte[] HeaderOnly(int width, int height) =>
        Craft(("IHDR", Ihdr(width, height)), ("IEND", []));

    /// <summary>
    /// The double-IHDR trick: a large first IHDR (what a decoder allocates from), an empty IDAT, then a tiny IHDR
    /// (what a header-only identify would report last).
    /// </summary>
    public static byte[] DoubleIhdr(int firstWidth, int firstHeight, int lastWidth, int lastHeight) =>
        Craft(("IHDR", Ihdr(firstWidth, firstHeight)), ("IDAT", []), ("IHDR", Ihdr(lastWidth, lastHeight)), ("IEND", []));

    public static byte[] Craft(params (string Type, byte[] Data)[] chunks)
    {
        using var output = new MemoryStream();
        output.Write(Signature);
        foreach (var (type, data) in chunks)
        {
            WriteChunk(output, type, data);
        }

        return output.ToArray();
    }

    public static byte[] Ihdr(int width, int height)
    {
        var ihdr = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(0, 4), width);
        BinaryPrimitives.WriteInt32BigEndian(ihdr.AsSpan(4, 4), height);
        ihdr[8] = 8; // bit depth
        ihdr[9] = 6; // RGBA
        return ihdr;
    }

    private static void WriteChunk(Stream output, string type, byte[] data)
    {
        var typeBytes = Encoding.ASCII.GetBytes(type);
        var length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, data.Length);
        output.Write(length);
        output.Write(typeBytes);
        output.Write(data);
        var crc = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crc, Crc32([.. typeBytes, .. data]));
        output.Write(crc);
    }

    private static uint Crc32(byte[] bytes)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in bytes)
        {
            crc ^= b;
            for (var i = 0; i < 8; i++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }
}
