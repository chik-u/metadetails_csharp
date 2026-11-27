using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Pure C# metadata reader and selective binary sanitizer for common formats
/// (JPEG, PNG, WebP, GIF, WAV, SVG). Used as a built-in engine when external CLI
/// tools (exiftool/ffmpeg) are unavailable, or for direct deterministic sanitization.
/// </summary>
public static class NativeBinaryMetadataHandler
{
    private static readonly byte[] ExifHeader = "Exif\0\0"u8.ToArray();
    private static readonly byte[] XmpHeader = "http://ns.adobe.com/xap/1.0/\0"u8.ToArray();
    private static readonly byte[] IccHeader = "ICC_Profile\0"u8.ToArray();
    private static readonly byte[] PngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    private static readonly HashSet<string> SupportedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".webp", ".gif", ".wav", ".svg"
    };

    public static bool IsSupported(string filePathOrExtension)
    {
        var ext = Path.GetExtension(filePathOrExtension);
        return SupportedExtensions.Contains(ext);
    }

    public static JsonObject ExtractMetadata(string filePath, string? originalFileName = null)
    {
        var bytes = File.ReadAllBytes(filePath);
        var ext = Path.GetExtension(originalFileName ?? filePath).ToLowerInvariant();
        var meta = new JsonObject
        {
            ["FileName"] = originalFileName ?? Path.GetFileName(filePath),
            ["FileSize"] = bytes.Length
        };

        switch (ext)
        {
            case ".jpg":
            case ".jpeg":
                meta["FileType"] = "JPEG";
                meta["FileTypeExtension"] = "jpg";
                meta["MIMEType"] = "image/jpeg";
                ExtractJpeg(bytes, meta);
                break;
            case ".png":
                meta["FileType"] = "PNG";
                meta["FileTypeExtension"] = "png";
                meta["MIMEType"] = "image/png";
                ExtractPng(bytes, meta);
                break;
            case ".webp":
                meta["FileType"] = "WEBP";
                meta["FileTypeExtension"] = "webp";
                meta["MIMEType"] = "image/webp";
                ExtractWebp(bytes, meta);
                break;
            case ".gif":
                meta["FileType"] = "GIF";
                meta["FileTypeExtension"] = "gif";
                meta["MIMEType"] = "image/gif";
                ExtractGif(bytes, meta);
                break;
            case ".wav":
                meta["FileType"] = "WAV";
                meta["FileTypeExtension"] = "wav";
                meta["MIMEType"] = "audio/wav";
                ExtractWav(bytes, meta);
                break;
            case ".svg":
                meta["FileType"] = "SVG";
                meta["FileTypeExtension"] = "svg";
                meta["MIMEType"] = "image/svg+xml";
                ExtractSvg(bytes, meta);
                break;
        }

        return meta;
    }

    /// <summary>
    /// Selectively removes metadata marked Remove in <paramref name="report"/> while preserving
    /// Required and Low-priority metadata in the output file.
    /// </summary>
    public static void SanitizeFile(string inputPath, string outputPath, MetaCoreReport report, string? originalFileName = null)
    {
        var bytes = File.ReadAllBytes(inputPath);
        var ext = Path.GetExtension(originalFileName ?? inputPath).ToLowerInvariant();
        var actions = BuildActionLookup(report);

        byte[] sanitized = ext switch
        {
            ".jpg" or ".jpeg" => SanitizeJpeg(bytes, actions),
            ".png" => SanitizePng(bytes, actions),
            ".webp" => SanitizeWebp(bytes, actions),
            ".gif" => SanitizeGif(bytes, actions),
            ".wav" => SanitizeWav(bytes, actions),
            ".svg" => SanitizeSvg(bytes, actions),
            _ => throw new NotSupportedException($"Native sanitizer does not support extension '{ext}'.")
        };

        File.WriteAllBytes(outputPath, sanitized);
    }

    private static Dictionary<string, MetaAction> BuildActionLookup(MetaCoreReport report)
    {
        var dict = new Dictionary<string, MetaAction>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in report.Details)
        {
            dict[item.Key] = item.Action;
            dict.TryAdd(item.NormalizedKey, item.Action);
        }
        return dict;
    }

    private static bool ShouldKeep(Dictionary<string, MetaAction> actions, string tagName, bool defaultKeep = false)
    {
        if (actions.TryGetValue(tagName, out var action))
            return action == MetaAction.Keep;
        return defaultKeep;
    }

    #region JPEG
    private static void ExtractJpeg(byte[] bytes, JsonObject meta)
    {
        if (bytes.Length < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8) return;
        int pos = 2;
        while (pos + 1 < bytes.Length)
        {
            if (bytes[pos] != 0xFF) { pos++; continue; }
            while (pos < bytes.Length && bytes[pos] == 0xFF) pos++;
            if (pos >= bytes.Length) break;
            byte marker = bytes[pos++];

            if (marker == 0xD9 || marker == 0xDA) break; // EOI or SOS
            if (marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;
            if (pos + 2 > bytes.Length) break;

            int segLen = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(pos, 2));
            if (segLen < 2 || pos + segLen > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 2, segLen - 2);

            if (marker == 0xE0 && payload.Length >= 14 && payload[..5].SequenceEqual("JFIF\0"u8))
            {
                meta["JFIFVersion"] = $"{payload[5]}.{payload[6]:D2}";
                meta["ResolutionUnit"] = payload[7] switch { 1 => "inches", 2 => "cm", _ => "None" };
                meta["XResolution"] = BinaryPrimitives.ReadUInt16BigEndian(payload[8..10]);
                meta["YResolution"] = BinaryPrimitives.ReadUInt16BigEndian(payload[10..12]);
            }
            else if (marker == 0xE1)
            {
                if (payload.Length > ExifHeader.Length && payload[..ExifHeader.Length].SequenceEqual(ExifHeader))
                {
                    ParseTiffExif(payload[ExifHeader.Length..].ToArray(), meta);
                }
                else if (payload.Length > XmpHeader.Length && payload[..XmpHeader.Length].SequenceEqual(XmpHeader))
                {
                    ParseXmp(Encoding.UTF8.GetString(payload[XmpHeader.Length..]), meta);
                }
            }
            else if (marker == 0xE2 && payload.Length > IccHeader.Length && payload[..IccHeader.Length].SequenceEqual(IccHeader))
            {
                meta["ICCProfileName"] = "Embedded ICC Profile";
            }
            else if (marker == 0xED)
            {
                meta["Photoshop:IPTCData"] = "Present";
            }
            else if (marker == 0xFE)
            {
                meta["Comment"] = Encoding.UTF8.GetString(payload).TrimEnd('\0');
            }
            else if (marker >= 0xC0 && marker <= 0xC3 && payload.Length >= 6)
            {
                meta["BitsPerSample"] = payload[0];
                meta["ImageHeight"] = BinaryPrimitives.ReadUInt16BigEndian(payload[1..3]);
                meta["ImageWidth"] = BinaryPrimitives.ReadUInt16BigEndian(payload[3..5]);
                meta["ColorComponents"] = payload[5];
            }

            pos += segLen;
        }
    }

    private static byte[] SanitizeJpeg(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        if (bytes.Length < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8)
            throw new InvalidDataException("Invalid JPEG file header.");

        using var ms = new MemoryStream();
        ms.WriteByte(0xFF);
        ms.WriteByte(0xD8);

        int pos = 2;
        while (pos + 1 < bytes.Length)
        {
            if (bytes[pos] != 0xFF) { pos++; continue; }
            while (pos < bytes.Length && bytes[pos] == 0xFF) pos++;
            if (pos >= bytes.Length) break;
            byte marker = bytes[pos++];

            if (marker == 0xDA) // SOS: copy remainder verbatim (image scan + EOI)
            {
                ms.WriteByte(0xFF);
                ms.WriteByte(marker);
                ms.Write(bytes, pos, bytes.Length - pos);
                break;
            }
            if (marker == 0xD9) // EOI
            {
                ms.WriteByte(0xFF);
                ms.WriteByte(0xD9);
                break;
            }
            if (marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
            {
                ms.WriteByte(0xFF);
                ms.WriteByte(marker);
                continue;
            }
            if (pos + 2 > bytes.Length) break;

            int segLen = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(pos, 2));
            if (segLen < 2 || pos + segLen > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 2, segLen - 2);

            if (marker == 0xE1)
            {
                if (payload.Length > ExifHeader.Length && payload[..ExifHeader.Length].SequenceEqual(ExifHeader))
                {
                    var rebuiltTiff = FilterTiffExif(payload[ExifHeader.Length..].ToArray(), actions);
                    if (rebuiltTiff != null)
                    {
                        var newPayload = new byte[ExifHeader.Length + rebuiltTiff.Length];
                        Buffer.BlockCopy(ExifHeader, 0, newPayload, 0, ExifHeader.Length);
                        Buffer.BlockCopy(rebuiltTiff, 0, newPayload, ExifHeader.Length, rebuiltTiff.Length);
                        WriteJpegSegment(ms, marker, newPayload);
                    }
                }
                else if (payload.Length > XmpHeader.Length && payload[..XmpHeader.Length].SequenceEqual(XmpHeader))
                {
                    var xmpXml = Encoding.UTF8.GetString(payload[XmpHeader.Length..]);
                    var filteredXmp = FilterXmp(xmpXml, actions);
                    if (!string.IsNullOrEmpty(filteredXmp))
                    {
                        var xmlBytes = Encoding.UTF8.GetBytes(filteredXmp);
                        var newPayload = new byte[XmpHeader.Length + xmlBytes.Length];
                        Buffer.BlockCopy(XmpHeader, 0, newPayload, 0, XmpHeader.Length);
                        Buffer.BlockCopy(xmlBytes, 0, newPayload, XmpHeader.Length, xmlBytes.Length);
                        WriteJpegSegment(ms, marker, newPayload);
                    }
                }
                // Other unknown APP1 blocks are dropped as potentially sensitive
            }
            else if (marker == 0xED)
            {
                // APP13 Photoshop / IPTC: drop unless explicitly overridden
                if (ShouldKeep(actions, "Photoshop:IPTCData"))
                    WriteJpegSegment(ms, marker, payload);
            }
            else if (marker == 0xFE)
            {
                // COM comment: drop unless explicitly overridden
                if (ShouldKeep(actions, "Comment"))
                    WriteJpegSegment(ms, marker, payload);
            }
            else if (marker == 0xE2)
            {
                // Keep ICC_Profile when Required color metadata is kept
                bool isIcc = payload.Length > IccHeader.Length && payload[..IccHeader.Length].SequenceEqual(IccHeader);
                if (!isIcc || ShouldKeep(actions, "ICCProfileName", defaultKeep: true))
                    WriteJpegSegment(ms, marker, payload);
            }
            else if (marker >= 0xE3 && marker <= 0xEF && marker != 0xEE)
            {
                // Strip vendor/proprietary APP3-APP15 metadata blocks (keeping APP14 Adobe color transform)
            }
            else
            {
                // APP0 (JFIF), APP14 (Adobe), DQT, DHT, SOF, DRI, etc.
                WriteJpegSegment(ms, marker, payload);
            }

            pos += segLen;
        }

        return ms.ToArray();
    }

    private static void WriteJpegSegment(Stream ms, byte marker, ReadOnlySpan<byte> payload)
    {
        ms.WriteByte(0xFF);
        ms.WriteByte(marker);
        Span<byte> lenBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lenBytes, (ushort)(payload.Length + 2));
        ms.Write(lenBytes);
        ms.Write(payload);
    }
    #endregion

    #region PNG
    private static void ExtractPng(byte[] bytes, JsonObject meta)
    {
        if (bytes.Length < 8 || !bytes.AsSpan(0, 8).SequenceEqual(PngSignature)) return;
        int pos = 8;
        while (pos + 12 <= bytes.Length)
        {
            uint len = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(pos, 4));
            if (pos + 12L + len > bytes.Length) break;
            var type = Encoding.ASCII.GetString(bytes, pos + 4, 4);
            var data = bytes.AsSpan(pos + 8, (int)len);

            switch (type)
            {
                case "IHDR" when data.Length >= 13:
                    meta["ImageWidth"] = BinaryPrimitives.ReadUInt32BigEndian(data[0..4]);
                    meta["ImageHeight"] = BinaryPrimitives.ReadUInt32BigEndian(data[4..8]);
                    meta["BitDepth"] = data[8];
                    meta["ColorType"] = data[9];
                    meta["Compression"] = data[10];
                    meta["Filter"] = data[11];
                    meta["Interlace"] = data[12];
                    break;
                case "pHYs" when data.Length >= 9:
                    meta["PixelsPerUnitX"] = BinaryPrimitives.ReadUInt32BigEndian(data[0..4]);
                    meta["PixelsPerUnitY"] = BinaryPrimitives.ReadUInt32BigEndian(data[4..8]);
                    meta["PixelUnits"] = data[8] == 1 ? "meters" : "Unknown";
                    break;
                case "sRGB" when data.Length >= 1:
                    meta["SRGBRendering"] = data[0];
                    break;
                case "gAMA" when data.Length >= 4:
                    meta["Gamma"] = BinaryPrimitives.ReadUInt32BigEndian(data[0..4]) / 100000.0;
                    break;
                case "iCCP":
                    int z = data.IndexOf((byte)0);
                    meta["ICCProfileName"] = z > 0 ? Encoding.Latin1.GetString(data[..z]) : "Embedded ICC Profile";
                    break;
                case "tIME" when data.Length >= 7:
                    int year = BinaryPrimitives.ReadUInt16BigEndian(data[0..2]);
                    meta["ModifyDate"] = $"{year:D4}:{data[2]:D2}:{data[3]:D2} {data[4]:D2}:{data[5]:D2}:{data[6]:D2}";
                    break;
                case "eXIf":
                    ParseTiffExif(data.ToArray(), meta);
                    break;
                case "tEXt":
                    ParsePngTextChunk(data, meta);
                    break;
                case "zTXt":
                    ParsePngZtxtChunk(data, meta);
                    break;
                case "iTXt":
                    ParsePngItxtChunk(data, meta);
                    break;
            }

            pos += 12 + (int)len;
        }
    }

    private static byte[] SanitizePng(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        if (bytes.Length < 8 || !bytes.AsSpan(0, 8).SequenceEqual(PngSignature))
            throw new InvalidDataException("Invalid PNG file signature.");

        using var ms = new MemoryStream();
        ms.Write(PngSignature);

        int pos = 8;
        while (pos + 12 <= bytes.Length)
        {
            uint len = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(pos, 4));
            if (pos + 12L + len > bytes.Length) break;
            var typeBytes = bytes.AsSpan(pos + 4, 4);
            var type = Encoding.ASCII.GetString(typeBytes);
            var data = bytes.AsSpan(pos + 8, (int)len);

            if (type == "tIME")
            {
                if (ShouldKeep(actions, "ModifyDate"))
                    WritePngChunk(ms, typeBytes, data);
            }
            else if (type == "eXIf")
            {
                var filtered = FilterTiffExif(data.ToArray(), actions);
                if (filtered != null)
                    WritePngChunk(ms, typeBytes, filtered);
            }
            else if (type is "tEXt" or "zTXt" or "iTXt")
            {
                int sep = data.IndexOf((byte)0);
                var keyword = sep > 0 ? Encoding.Latin1.GetString(data[..sep]) : string.Empty;
                if (keyword.Equals("XML:com.adobe.xmp", StringComparison.OrdinalIgnoreCase) && type == "iTXt")
                {
                    var xmpText = ExtractItxtPayload(data, sep);
                    var filteredXmp = xmpText != null ? FilterXmp(xmpText, actions) : null;
                    if (!string.IsNullOrEmpty(filteredXmp))
                    {
                        var rebuilt = BuildUncompressedItxt(keyword, filteredXmp);
                        WritePngChunk(ms, typeBytes, rebuilt);
                    }
                }
                else if (!string.IsNullOrEmpty(keyword) && ShouldKeep(actions, keyword))
                {
                    WritePngChunk(ms, typeBytes, data);
                }
            }
            else if (type == "iCCP")
            {
                if (ShouldKeep(actions, "ICCProfileName", defaultKeep: true))
                    WritePngChunk(ms, typeBytes, data);
            }
            else
            {
                // Preserve IHDR, PLTE, IDAT, IEND, sRGB, gAMA, cHRM, pHYs, tRNS, bKGD, etc.
                WritePngChunk(ms, typeBytes, data);
            }

            pos += 12 + (int)len;
        }

        return ms.ToArray();
    }

    private static void ParsePngTextChunk(ReadOnlySpan<byte> data, JsonObject meta)
    {
        int sep = data.IndexOf((byte)0);
        if (sep <= 0) return;
        var key = Encoding.Latin1.GetString(data[..sep]);
        var val = Encoding.Latin1.GetString(data[(sep + 1)..]);
        meta[key] = val;
    }

    private static void ParsePngZtxtChunk(ReadOnlySpan<byte> data, JsonObject meta)
    {
        int sep = data.IndexOf((byte)0);
        if (sep <= 0 || sep + 2 >= data.Length) return;
        var key = Encoding.Latin1.GetString(data[..sep]);
        if (data[sep + 1] != 0) return; // only deflate compression (0)
        try
        {
            using var compressed = new MemoryStream(data[(sep + 2)..].ToArray());
            using var zlib = new ZLibStream(compressed, CompressionMode.Decompress);
            using var output = new MemoryStream();
            zlib.CopyTo(output);
            meta[key] = Encoding.Latin1.GetString(output.ToArray());
        }
        catch { }
    }

    private static void ParsePngItxtChunk(ReadOnlySpan<byte> data, JsonObject meta)
    {
        int sep = data.IndexOf((byte)0);
        if (sep <= 0) return;
        var key = Encoding.Latin1.GetString(data[..sep]);
        var text = ExtractItxtPayload(data, sep);
        if (text == null) return;

        if (key.Equals("XML:com.adobe.xmp", StringComparison.OrdinalIgnoreCase))
            ParseXmp(text, meta);
        else
            meta[key] = text;
    }

    private static string? ExtractItxtPayload(ReadOnlySpan<byte> data, int keyNullIndex)
    {
        if (keyNullIndex + 3 >= data.Length) return null;
        byte compFlag = data[keyNullIndex + 1];
        byte compMethod = data[keyNullIndex + 2];
        int p = keyNullIndex + 3;
        int langEnd = data[p..].IndexOf((byte)0);
        if (langEnd < 0) return null;
        p += langEnd + 1;
        if (p >= data.Length) return null;
        int transEnd = data[p..].IndexOf((byte)0);
        if (transEnd < 0) return null;
        p += transEnd + 1;
        if (p > data.Length) return null;

        var rawText = data[p..];
        if (compFlag == 0)
            return Encoding.UTF8.GetString(rawText);

        if (compFlag == 1 && compMethod == 0)
        {
            try
            {
                using var ms = new MemoryStream(rawText.ToArray());
                using var zlib = new ZLibStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                zlib.CopyTo(outMs);
                return Encoding.UTF8.GetString(outMs.ToArray());
            }
            catch { return null; }
        }
        return null;
    }

    private static byte[] BuildUncompressedItxt(string keyword, string utf8Text)
    {
        using var ms = new MemoryStream();
        ms.Write(Encoding.Latin1.GetBytes(keyword));
        ms.WriteByte(0); // null separator
        ms.WriteByte(0); // compression flag = 0
        ms.WriteByte(0); // compression method = 0
        ms.WriteByte(0); // empty language tag
        ms.WriteByte(0); // empty translated keyword
        ms.Write(Encoding.UTF8.GetBytes(utf8Text));
        return ms.ToArray();
    }

    private static void WritePngChunk(Stream ms, ReadOnlySpan<byte> type, ReadOnlySpan<byte> data)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)data.Length);
        ms.Write(buf);
        ms.Write(type);
        ms.Write(data);

        uint crc = ComputePngCrc32(type, data);
        BinaryPrimitives.WriteUInt32BigEndian(buf, crc);
        ms.Write(buf);
    }

    private static uint ComputePngCrc32(ReadOnlySpan<byte> type, ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        crc = UpdateCrc32(crc, type);
        crc = UpdateCrc32(crc, data);
        return crc ^ 0xFFFFFFFF;
    }

    private static uint UpdateCrc32(uint crc, ReadOnlySpan<byte> span)
    {
        foreach (byte b in span)
        {
            crc ^= b;
            for (int k = 0; k < 8; k++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
        return crc;
    }
    #endregion

    #region WebP
    private static void ExtractWebp(byte[] bytes, JsonObject meta)
    {
        if (bytes.Length < 12 || !bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8) || !bytes.AsSpan(8, 4).SequenceEqual("WEBP"u8))
            return;

        int pos = 12;
        while (pos + 8 <= bytes.Length)
        {
            var fourcc = Encoding.ASCII.GetString(bytes, pos, 4);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(pos + 4, 4));
            if (pos + 8L + size > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 8, (int)size);

            if (fourcc == "VP8X" && payload.Length >= 10)
            {
                meta["ImageWidth"] = 1 + (payload[4] | (payload[5] << 8) | (payload[6] << 16));
                meta["ImageHeight"] = 1 + (payload[7] | (payload[8] << 8) | (payload[9] << 16));
            }
            else if (fourcc == "ICCP")
            {
                meta["ICCProfileName"] = "Embedded ICC Profile";
            }
            else if (fourcc == "EXIF")
            {
                var tiffSpan = payload.Length > ExifHeader.Length && payload[..ExifHeader.Length].SequenceEqual(ExifHeader)
                    ? payload[ExifHeader.Length..]
                    : payload;
                ParseTiffExif(tiffSpan.ToArray(), meta);
            }
            else if (fourcc == "XMP ")
            {
                ParseXmp(Encoding.UTF8.GetString(payload), meta);
            }

            pos += 8 + (int)size + ((int)size & 1);
        }
    }

    private static byte[] SanitizeWebp(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        if (bytes.Length < 12 || !bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8) || !bytes.AsSpan(8, 4).SequenceEqual("WEBP"u8))
            throw new InvalidDataException("Invalid WebP RIFF header.");

        var chunks = new List<(string FourCC, byte[] Data)>();
        bool hasExifAfter = false;
        bool hasXmpAfter = false;

        int pos = 12;
        while (pos + 8 <= bytes.Length)
        {
            var fourcc = Encoding.ASCII.GetString(bytes, pos, 4);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(pos + 4, 4));
            if (pos + 8L + size > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 8, (int)size);

            if (fourcc == "EXIF")
            {
                bool hadPrefix = payload.Length > ExifHeader.Length && payload[..ExifHeader.Length].SequenceEqual(ExifHeader);
                var tiffBytes = hadPrefix ? payload[ExifHeader.Length..].ToArray() : payload.ToArray();
                var filtered = FilterTiffExif(tiffBytes, actions);
                if (filtered != null)
                {
                    hasExifAfter = true;
                    chunks.Add((fourcc, filtered));
                }
            }
            else if (fourcc == "XMP ")
            {
                var filteredXmp = FilterXmp(Encoding.UTF8.GetString(payload), actions);
                if (!string.IsNullOrEmpty(filteredXmp))
                {
                    hasXmpAfter = true;
                    chunks.Add((fourcc, Encoding.UTF8.GetBytes(filteredXmp)));
                }
            }
            else if (fourcc == "ICCP")
            {
                if (ShouldKeep(actions, "ICCProfileName", defaultKeep: true))
                    chunks.Add((fourcc, payload.ToArray()));
            }
            else
            {
                chunks.Add((fourcc, payload.ToArray()));
            }

            pos += 8 + (int)size + ((int)size & 1);
        }

        // Update VP8X header feature flags (bit 3 = EXIF 0x08, bit 2 = XMP 0x04)
        for (int i = 0; i < chunks.Count; i++)
        {
            if (chunks[i].FourCC == "VP8X" && chunks[i].Data.Length >= 10)
            {
                byte flags = chunks[i].Data[0];
                flags = hasExifAfter ? (byte)(flags | 0x08) : (byte)(flags & ~0x08);
                flags = hasXmpAfter ? (byte)(flags | 0x04) : (byte)(flags & ~0x04);
                chunks[i].Data[0] = flags;
            }
        }

        using var body = new MemoryStream();
        body.Write("WEBP"u8);
        Span<byte> lenBytes = stackalloc byte[4];
        foreach (var (fourcc, data) in chunks)
        {
            body.Write(Encoding.ASCII.GetBytes(fourcc));
            BinaryPrimitives.WriteUInt32LittleEndian(lenBytes, (uint)data.Length);
            body.Write(lenBytes);
            body.Write(data);
            if ((data.Length & 1) == 1) body.WriteByte(0);
        }

        var result = new byte[8 + body.Length];
        "RIFF"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), (uint)body.Length);
        body.ToArray().CopyTo(result, 8);
        return result;
    }
    #endregion

    #region GIF
    private static void ExtractGif(byte[] bytes, JsonObject meta)
    {
        if (bytes.Length < 13 || (!bytes.AsSpan(0, 6).SequenceEqual("GIF89a"u8) && !bytes.AsSpan(0, 6).SequenceEqual("GIF87a"u8)))
            return;

        meta["ImageWidth"] = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(6, 2));
        meta["ImageHeight"] = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(8, 2));

        int pos = 13;
        byte packed = bytes[10];
        if ((packed & 0x80) != 0)
        {
            int gctSize = 3 * (1 << ((packed & 0x07) + 1));
            pos += gctSize;
        }

        var comments = new List<string>();
        while (pos < bytes.Length)
        {
            byte intro = bytes[pos++];
            if (intro == 0x3B) break;
            if (intro == 0x2C) // Image descriptor
            {
                if (pos + 9 > bytes.Length) break;
                byte imgPacked = bytes[pos + 8];
                pos += 9;
                if ((imgPacked & 0x80) != 0) pos += 3 * (1 << ((imgPacked & 0x07) + 1));
                if (pos >= bytes.Length) break;
                pos++; // LZW min code size
                SkipGifSubBlocks(bytes, ref pos);
            }
            else if (intro == 0x21)
            {
                if (pos >= bytes.Length) break;
                byte label = bytes[pos++];
                if (label == 0xFE)
                {
                    var commentBytes = ReadGifSubBlocks(bytes, ref pos);
                    comments.Add(Encoding.UTF8.GetString(commentBytes));
                }
                else if (label == 0xFF)
                {
                    int appStart = pos;
                    if (pos < bytes.Length && bytes[pos] == 11 && pos + 12 <= bytes.Length)
                    {
                        var appId = Encoding.ASCII.GetString(bytes, pos + 1, 11);
                        pos += 12;
                        var subData = ReadGifSubBlocks(bytes, ref pos);
                        if (appId == "XMP DataXMP")
                            ParseXmp(Encoding.UTF8.GetString(subData), meta);
                    }
                    else
                    {
                        pos = appStart;
                        SkipGifSubBlocks(bytes, ref pos);
                    }
                }
                else
                {
                    SkipGifSubBlocks(bytes, ref pos);
                }
            }
            else break;
        }

        if (comments.Count > 0)
            meta["Comment"] = string.Join("\n", comments);
    }

    private static byte[] SanitizeGif(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        if (bytes.Length < 13 || (!bytes.AsSpan(0, 6).SequenceEqual("GIF89a"u8) && !bytes.AsSpan(0, 6).SequenceEqual("GIF87a"u8)))
            throw new InvalidDataException("Invalid GIF header.");

        using var ms = new MemoryStream();
        int headerEnd = 13;
        byte packed = bytes[10];
        if ((packed & 0x80) != 0)
            headerEnd += 3 * (1 << ((packed & 0x07) + 1));
        if (headerEnd > bytes.Length) throw new InvalidDataException("Truncated GIF color table.");

        ms.Write(bytes, 0, headerEnd);
        int pos = headerEnd;

        while (pos < bytes.Length)
        {
            int blockStart = pos;
            byte intro = bytes[pos++];
            if (intro == 0x3B)
            {
                ms.WriteByte(0x3B);
                break;
            }
            if (intro == 0x2C)
            {
                if (pos + 9 > bytes.Length) break;
                byte imgPacked = bytes[pos + 8];
                pos += 9;
                if ((imgPacked & 0x80) != 0) pos += 3 * (1 << ((imgPacked & 0x07) + 1));
                if (pos >= bytes.Length) break;
                pos++;
                SkipGifSubBlocks(bytes, ref pos);
                ms.Write(bytes, blockStart, pos - blockStart);
            }
            else if (intro == 0x21)
            {
                if (pos >= bytes.Length) break;
                byte label = bytes[pos++];
                if (label == 0xFE)
                {
                    SkipGifSubBlocks(bytes, ref pos);
                    if (ShouldKeep(actions, "Comment"))
                        ms.Write(bytes, blockStart, pos - blockStart);
                }
                else if (label == 0xFF && pos < bytes.Length && bytes[pos] == 11 && pos + 12 <= bytes.Length)
                {
                    var appId = Encoding.ASCII.GetString(bytes, pos + 1, 11);
                    pos += 12;
                    SkipGifSubBlocks(bytes, ref pos);
                    if (appId != "XMP DataXMP")
                        ms.Write(bytes, blockStart, pos - blockStart);
                }
                else
                {
                    SkipGifSubBlocks(bytes, ref pos);
                    ms.Write(bytes, blockStart, pos - blockStart);
                }
            }
            else break;
        }

        return ms.ToArray();
    }

    private static void SkipGifSubBlocks(byte[] bytes, ref int pos)
    {
        while (pos < bytes.Length)
        {
            byte len = bytes[pos++];
            if (len == 0) break;
            pos = Math.Min(bytes.Length, pos + len);
        }
    }

    private static byte[] ReadGifSubBlocks(byte[] bytes, ref int pos)
    {
        using var ms = new MemoryStream();
        while (pos < bytes.Length)
        {
            byte len = bytes[pos++];
            if (len == 0) break;
            int take = Math.Min(len, bytes.Length - pos);
            ms.Write(bytes, pos, take);
            pos += take;
        }
        return ms.ToArray();
    }
    #endregion

    #region WAV
    private static readonly Dictionary<string, string> RiffInfoTagMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["INAM"] = "Title",
        ["IART"] = "Artist",
        ["ICMT"] = "Comment",
        ["ICRD"] = "DateCreated",
        ["ISFT"] = "Software",
        ["ICOP"] = "Copyright",
        ["IENG"] = "Author",
        ["IGNR"] = "Genre"
    };

    private static void ExtractWav(byte[] bytes, JsonObject meta)
    {
        if (bytes.Length < 12 || !bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8) || !bytes.AsSpan(8, 4).SequenceEqual("WAVE"u8))
            return;

        int pos = 12;
        while (pos + 8 <= bytes.Length)
        {
            var id = Encoding.ASCII.GetString(bytes, pos, 4);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(pos + 4, 4));
            if (pos + 8L + size > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 8, (int)size);

            if (id == "fmt " && payload.Length >= 16)
            {
                meta["AudioChannels"] = BinaryPrimitives.ReadUInt16LittleEndian(payload[2..4]);
                meta["SampleRate"] = BinaryPrimitives.ReadUInt32LittleEndian(payload[4..8]);
                meta["AudioBitsPerSample"] = BinaryPrimitives.ReadUInt16LittleEndian(payload[14..16]);
            }
            else if (id == "LIST" && payload.Length >= 4 && payload[..4].SequenceEqual("INFO"u8))
            {
                int subPos = 4;
                while (subPos + 8 <= payload.Length)
                {
                    var subId = Encoding.ASCII.GetString(payload.Slice(subPos, 4));
                    uint subLen = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(subPos + 4, 4));
                    if (subPos + 8L + subLen > payload.Length) break;
                    var val = Encoding.UTF8.GetString(payload.Slice(subPos + 8, (int)subLen)).TrimEnd('\0');
                    var mapped = RiffInfoTagMap.GetValueOrDefault(subId, subId);
                    meta[mapped] = val;
                    subPos += 8 + (int)subLen + ((int)subLen & 1);
                }
            }
            else if (id.Equals("id3 ", StringComparison.OrdinalIgnoreCase))
            {
                meta["ID3Tag"] = "Present";
            }

            pos += 8 + (int)size + ((int)size & 1);
        }
    }

    private static byte[] SanitizeWav(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        if (bytes.Length < 12 || !bytes.AsSpan(0, 4).SequenceEqual("RIFF"u8) || !bytes.AsSpan(8, 4).SequenceEqual("WAVE"u8))
            throw new InvalidDataException("Invalid WAV RIFF header.");

        using var body = new MemoryStream();
        body.Write("WAVE"u8);

        int pos = 12;
        Span<byte> lenBuf = stackalloc byte[4];
        while (pos + 8 <= bytes.Length)
        {
            var id = Encoding.ASCII.GetString(bytes, pos, 4);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(pos + 4, 4));
            if (pos + 8L + size > bytes.Length) break;
            var payload = bytes.AsSpan(pos + 8, (int)size);

            if (id == "LIST" && payload.Length >= 4 && payload[..4].SequenceEqual("INFO"u8))
            {
                using var infoMs = new MemoryStream();
                infoMs.Write("INFO"u8);
                int subPos = 4;
                int keptCount = 0;
                while (subPos + 8 <= payload.Length)
                {
                    var subId = Encoding.ASCII.GetString(payload.Slice(subPos, 4));
                    uint subLen = BinaryPrimitives.ReadUInt32LittleEndian(payload.Slice(subPos + 4, 4));
                    if (subPos + 8L + subLen > payload.Length) break;
                    var mapped = RiffInfoTagMap.GetValueOrDefault(subId, subId);
                    if (ShouldKeep(actions, mapped))
                    {
                        keptCount++;
                        var subPayload = payload.Slice(subPos + 8, (int)subLen);
                        infoMs.Write(Encoding.ASCII.GetBytes(subId));
                        BinaryPrimitives.WriteUInt32LittleEndian(lenBuf, subLen);
                        infoMs.Write(lenBuf);
                        infoMs.Write(subPayload);
                        if ((subLen & 1) == 1) infoMs.WriteByte(0);
                    }
                    subPos += 8 + (int)subLen + ((int)subLen & 1);
                }

                if (keptCount > 0)
                    WriteRiffChunk(body, "LIST", infoMs.ToArray());
            }
            else if (id.Equals("id3 ", StringComparison.OrdinalIgnoreCase) || id == "bext" || id == "iXML")
            {
                // Strip embedded metadata chunks unless explicitly kept
                if (ShouldKeep(actions, id.Trim()))
                    WriteRiffChunk(body, id, payload);
            }
            else
            {
                WriteRiffChunk(body, id, payload);
            }

            pos += 8 + (int)size + ((int)size & 1);
        }

        var result = new byte[8 + body.Length];
        "RIFF"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), (uint)body.Length);
        body.ToArray().CopyTo(result, 8);
        return result;
    }

    private static void WriteRiffChunk(Stream ms, string fourcc, ReadOnlySpan<byte> payload)
    {
        ms.Write(Encoding.ASCII.GetBytes(fourcc));
        Span<byte> lenBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lenBytes, (uint)payload.Length);
        ms.Write(lenBytes);
        ms.Write(payload);
        if ((payload.Length & 1) == 1) ms.WriteByte(0);
    }
    #endregion

    #region SVG
    private static void ExtractSvg(byte[] bytes, JsonObject meta)
    {
        try
        {
            using var ms = new MemoryStream(bytes);
            var doc = XDocument.Load(ms, LoadOptions.PreserveWhitespace);
            var root = doc.Root;
            if (root == null) return;

            var width = root.Attribute("width")?.Value;
            var height = root.Attribute("height")?.Value;
            if (!string.IsNullOrEmpty(width)) meta["ImageWidth"] = width;
            if (!string.IsNullOrEmpty(height)) meta["ImageHeight"] = height;

            foreach (var attr in root.Attributes())
            {
                var ns = attr.Name.NamespaceName;
                if (ns.Contains("inkscape", StringComparison.OrdinalIgnoreCase))
                    meta[$"inkscape:{attr.Name.LocalName}"] = attr.Value;
                else if (ns.Contains("sodipodi", StringComparison.OrdinalIgnoreCase))
                    meta[$"sodipodi:{attr.Name.LocalName}"] = attr.Value;
            }

            foreach (var el in root.Descendants())
            {
                if (el.Name.LocalName.Equals("metadata", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var leaf in el.Descendants().Where(d => !d.HasElements && !string.IsNullOrWhiteSpace(d.Value)))
                        meta[leaf.Name.LocalName] = leaf.Value.Trim();
                }
                else if (el.Parent == root && el.Name.LocalName is "title" or "desc" && !string.IsNullOrWhiteSpace(el.Value))
                {
                    meta[el.Name.LocalName == "title" ? "Title" : "Description"] = el.Value.Trim();
                }
            }

            var comments = doc.DescendantNodes().OfType<XComment>().Select(c => c.Value.Trim()).Where(c => c.Length > 0).ToList();
            if (comments.Count > 0) meta["Comment"] = string.Join("\n", comments);
        }
        catch { }
    }

    private static byte[] SanitizeSvg(byte[] bytes, Dictionary<string, MetaAction> actions)
    {
        using var ms = new MemoryStream(bytes);
        var doc = XDocument.Load(ms, LoadOptions.PreserveWhitespace);
        var root = doc.Root ?? throw new InvalidDataException("Invalid SVG XML.");

        if (!ShouldKeep(actions, "Comment"))
        {
            foreach (var c in doc.DescendantNodes().OfType<XComment>().ToList())
                c.Remove();
        }

        foreach (var el in root.Descendants().Where(e => e.Name.LocalName.Equals("metadata", StringComparison.OrdinalIgnoreCase)).ToList())
            el.Remove();

        foreach (var el in root.Descendants().Where(e => e.Name.NamespaceName.Contains("sodipodi", StringComparison.OrdinalIgnoreCase) ||
                                                          e.Name.NamespaceName.Contains("inkscape", StringComparison.OrdinalIgnoreCase)).ToList())
            el.Remove();

        if (!ShouldKeep(actions, "Title"))
            foreach (var el in root.Elements().Where(e => e.Name.LocalName == "title").ToList()) el.Remove();

        if (!ShouldKeep(actions, "Description"))
            foreach (var el in root.Elements().Where(e => e.Name.LocalName == "desc").ToList()) el.Remove();

        foreach (var attr in root.DescendantsAndSelf().SelectMany(e => e.Attributes()).Where(a => !a.IsNamespaceDeclaration).ToList())
        {
            var ns = attr.Name.NamespaceName;
            string? prefix = ns.Contains("inkscape", StringComparison.OrdinalIgnoreCase)
                ? "inkscape"
                : ns.Contains("sodipodi", StringComparison.OrdinalIgnoreCase)
                    ? "sodipodi"
                    : null;

            if (prefix != null && !ShouldKeep(actions, $"{prefix}:{attr.Name.LocalName}"))
            {
                attr.Remove();
            }
        }

        // Remove editor namespace declarations only after referencing attributes/elements are gone
        var usedNamespaces = root.DescendantsAndSelf()
            .Select(e => e.Name.NamespaceName)
            .Concat(root.DescendantsAndSelf().SelectMany(e => e.Attributes()).Where(a => !a.IsNamespaceDeclaration).Select(a => a.Name.NamespaceName))
            .ToHashSet();

        foreach (var nsAttr in root.DescendantsAndSelf().SelectMany(e => e.Attributes()).Where(a => a.IsNamespaceDeclaration).ToList())
        {
            if ((nsAttr.Value.Contains("inkscape", StringComparison.OrdinalIgnoreCase) ||
                 nsAttr.Value.Contains("sodipodi", StringComparison.OrdinalIgnoreCase)) &&
                !usedNamespaces.Contains(nsAttr.Value))
            {
                nsAttr.Remove();
            }
        }

        return new UTF8Encoding(false).GetBytes(doc.ToString(SaveOptions.DisableFormatting));
    }
    #endregion

    #region TIFF / EXIF Reader & Rebuilder
    private sealed record TiffEntry(ushort Tag, ushort Type, uint Count, byte[] RawBytes);

    private static readonly Dictionary<ushort, string> Ifd0TagNames = new()
    {
        [0x0100] = "ImageWidth",
        [0x0101] = "ImageHeight",
        [0x0102] = "BitsPerSample",
        [0x0103] = "Compression",
        [0x010E] = "ImageDescription",
        [0x010F] = "Make",
        [0x0110] = "Model",
        [0x0112] = "Orientation",
        [0x011A] = "XResolution",
        [0x011B] = "YResolution",
        [0x0128] = "ResolutionUnit",
        [0x0131] = "Software",
        [0x0132] = "ModifyDate",
        [0x013B] = "Artist",
        [0x013C] = "HostComputer",
        [0x0213] = "YCbCrPositioning",
        [0x8298] = "Copyright",
        [0x9C9B] = "XPTitle",
        [0x9C9C] = "XPComment",
        [0x9C9D] = "XPAuthor",
        [0x9C9E] = "XPKeywords",
        [0x9C9F] = "XPSubject"
    };

    private static readonly Dictionary<ushort, string> ExifIfdTagNames = new()
    {
        [0x829A] = "ExposureTime",
        [0x829D] = "FNumber",
        [0x8822] = "ExposureProgram",
        [0x8827] = "ISO",
        [0x8830] = "SensitivityType",
        [0x8832] = "RecommendedExposureIndex",
        [0x9000] = "ExifVersion",
        [0x9003] = "DateTimeOriginal",
        [0x9004] = "CreateDate",
        [0x9010] = "OffsetTime",
        [0x9011] = "OffsetTimeOriginal",
        [0x9012] = "OffsetTimeDigitized",
        [0x9101] = "ComponentsConfiguration",
        [0x9102] = "CompressedBitsPerPixel",
        [0x9201] = "ShutterSpeedValue",
        [0x9202] = "ApertureValue",
        [0x9203] = "BrightnessValue",
        [0x9204] = "ExposureCompensation",
        [0x9205] = "MaxApertureValue",
        [0x9206] = "SubjectDistance",
        [0x9207] = "MeteringMode",
        [0x9208] = "LightSource",
        [0x9209] = "Flash",
        [0x920A] = "FocalLength",
        [0x927C] = "MakerNotes",
        [0x9286] = "UserComment",
        [0x9290] = "SubSecTime",
        [0x9291] = "SubSecTimeOriginal",
        [0x9292] = "SubSecTimeDigitized",
        [0xA000] = "FlashpixVersion",
        [0xA001] = "ColorSpace",
        [0xA002] = "ExifImageWidth",
        [0xA003] = "ExifImageHeight",
        [0xA217] = "SensingMethod",
        [0xA300] = "FileSource",
        [0xA301] = "SceneType",
        [0xA401] = "CustomRendered",
        [0xA402] = "ExposureMode",
        [0xA403] = "WhiteBalance",
        [0xA404] = "DigitalZoomRatio",
        [0xA405] = "FocalLengthIn35mmFormat",
        [0xA406] = "SceneCaptureType",
        [0xA407] = "GainControl",
        [0xA408] = "Contrast",
        [0xA409] = "Saturation",
        [0xA40A] = "Sharpness",
        [0xA40C] = "SubjectDistanceRange",
        [0xA420] = "ImageUniqueID",
        [0xA430] = "CameraOwnerName",
        [0xA431] = "SerialNumber",
        [0xA432] = "LensInfo",
        [0xA433] = "LensMake",
        [0xA434] = "LensModel",
        [0xA435] = "LensSerialNumber"
    };

    private static readonly Dictionary<ushort, string> GpsTagNames = new()
    {
        [0x0000] = "GPSVersionID",
        [0x0001] = "GPSLatitudeRef",
        [0x0002] = "GPSLatitude",
        [0x0003] = "GPSLongitudeRef",
        [0x0004] = "GPSLongitude",
        [0x0005] = "GPSAltitudeRef",
        [0x0006] = "GPSAltitude",
        [0x0007] = "GPSTimeStamp",
        [0x001D] = "GPSDateStamp"
    };

    private static void ParseTiffExif(byte[] tiff, JsonObject meta)
    {
        if (tiff.Length < 8) return;
        bool littleEndian = tiff[0] == (byte)'I' && tiff[1] == (byte)'I';
        if (!littleEndian && !(tiff[0] == (byte)'M' && tiff[1] == (byte)'M')) return;
        if (ReadU16(tiff, 2, littleEndian) != 42) return;

        meta["ExifByteOrder"] = littleEndian ? "Little-endian (Intel, II)" : "Big-endian (Motorola, MM)";
        uint ifd0Offset = ReadU32(tiff, 4, littleEndian);
        var (ifd0, nextIfd) = ReadIfd(tiff, ifd0Offset, littleEndian);

        foreach (var entry in ifd0)
        {
            if (entry.Tag == 0x8769 && entry.RawBytes.Length >= 4)
            {
                uint exifOffset = ReadU32(entry.RawBytes, 0, littleEndian);
                var (exifIfd, _) = ReadIfd(tiff, exifOffset, littleEndian);
                foreach (var e in exifIfd)
                {
                    var name = ExifIfdTagNames.GetValueOrDefault(e.Tag, $"ExifTag_0x{e.Tag:X4}");
                    meta[name] = DecodeTiffValue(e, littleEndian);
                }
            }
            else if (entry.Tag == 0x8825 && entry.RawBytes.Length >= 4)
            {
                uint gpsOffset = ReadU32(entry.RawBytes, 0, littleEndian);
                var (gpsIfd, _) = ReadIfd(tiff, gpsOffset, littleEndian);
                foreach (var g in gpsIfd)
                {
                    var name = GpsTagNames.GetValueOrDefault(g.Tag, $"GPSTag_0x{g.Tag:X4}");
                    meta[name] = DecodeTiffValue(g, littleEndian);
                }
            }
            else
            {
                var name = Ifd0TagNames.GetValueOrDefault(entry.Tag, $"IFD0Tag_0x{entry.Tag:X4}");
                meta[name] = DecodeTiffValue(entry, littleEndian);
            }
        }

        if (nextIfd > 0 && nextIfd < tiff.Length)
            meta["ThumbnailImage"] = "(Embedded IFD1 Thumbnail)";
    }

    private static byte[]? FilterTiffExif(byte[] tiff, Dictionary<string, MetaAction> actions)
    {
        if (tiff.Length < 8) return null;
        bool littleEndian = tiff[0] == (byte)'I' && tiff[1] == (byte)'I';
        if (!littleEndian && !(tiff[0] == (byte)'M' && tiff[1] == (byte)'M')) return null;
        if (ReadU16(tiff, 2, littleEndian) != 42) return null;

        uint ifd0Offset = ReadU32(tiff, 4, littleEndian);
        var (ifd0, _) = ReadIfd(tiff, ifd0Offset, littleEndian);

        var keptIfd0 = new List<TiffEntry>();
        var keptExif = new List<TiffEntry>();
        var keptGps = new List<TiffEntry>();

        foreach (var entry in ifd0)
        {
            if (entry.Tag == 0x8769 && entry.RawBytes.Length >= 4)
            {
                uint exifOffset = ReadU32(entry.RawBytes, 0, littleEndian);
                var (exifIfd, _) = ReadIfd(tiff, exifOffset, littleEndian);
                foreach (var e in exifIfd)
                {
                    var name = ExifIfdTagNames.GetValueOrDefault(e.Tag, $"ExifTag_0x{e.Tag:X4}");
                    if (ShouldKeep(actions, name))
                        keptExif.Add(e);
                }
            }
            else if (entry.Tag == 0x8825 && entry.RawBytes.Length >= 4)
            {
                uint gpsOffset = ReadU32(entry.RawBytes, 0, littleEndian);
                var (gpsIfd, _) = ReadIfd(tiff, gpsOffset, littleEndian);
                foreach (var g in gpsIfd)
                {
                    var name = GpsTagNames.GetValueOrDefault(g.Tag, $"GPSTag_0x{g.Tag:X4}");
                    if (ShouldKeep(actions, name))
                        keptGps.Add(g);
                }
            }
            else
            {
                var name = Ifd0TagNames.GetValueOrDefault(entry.Tag, $"IFD0Tag_0x{entry.Tag:X4}");
                if (ShouldKeep(actions, name))
                    keptIfd0.Add(entry);
            }
        }

        if (keptIfd0.Count == 0 && keptExif.Count == 0 && keptGps.Count == 0)
            return null;

        // Calculate IFD0 size including pointer entries for keptExif / keptGps
        var ifd0WithPtrs = new List<TiffEntry>(keptIfd0);
        if (keptExif.Count > 0) ifd0WithPtrs.Add(new TiffEntry(0x8769, 4, 1, new byte[4]));
        if (keptGps.Count > 0) ifd0WithPtrs.Add(new TiffEntry(0x8825, 4, 1, new byte[4]));

        uint ifd0Start = 8;
        uint ifd0Size = MeasureIfdSize(ifd0WithPtrs);
        uint exifOffsetOut = ifd0Start + ifd0Size;
        uint exifSize = keptExif.Count > 0 ? MeasureIfdSize(keptExif) : 0;
        uint gpsOffsetOut = exifOffsetOut + exifSize;

        // Replace placeholder pointer payloads with exact computed offsets
        for (int i = 0; i < ifd0WithPtrs.Count; i++)
        {
            if (ifd0WithPtrs[i].Tag == 0x8769)
            {
                var buf = new byte[4];
                WriteU32(buf, 0, exifOffsetOut, littleEndian);
                ifd0WithPtrs[i] = ifd0WithPtrs[i] with { RawBytes = buf };
            }
            else if (ifd0WithPtrs[i].Tag == 0x8825)
            {
                var buf = new byte[4];
                WriteU32(buf, 0, gpsOffsetOut, littleEndian);
                ifd0WithPtrs[i] = ifd0WithPtrs[i] with { RawBytes = buf };
            }
        }

        using var ms = new MemoryStream();
        ms.WriteByte(littleEndian ? (byte)'I' : (byte)'M');
        ms.WriteByte(littleEndian ? (byte)'I' : (byte)'M');
        Span<byte> hdr = stackalloc byte[6];
        WriteU16(hdr, 0, 42, littleEndian);
        WriteU32(hdr, 2, ifd0Start, littleEndian);
        ms.Write(hdr);

        WriteIfd(ms, ifd0WithPtrs, ifd0Start, 0, littleEndian);
        if (keptExif.Count > 0) WriteIfd(ms, keptExif, exifOffsetOut, 0, littleEndian);
        if (keptGps.Count > 0) WriteIfd(ms, keptGps, gpsOffsetOut, 0, littleEndian);

        return ms.ToArray();
    }

    private static (List<TiffEntry> Entries, uint NextIfdOffset) ReadIfd(byte[] tiff, uint offset, bool littleEndian)
    {
        var list = new List<TiffEntry>();
        if (offset == 0 || offset + 2 > tiff.Length) return (list, 0);

        ushort count = ReadU16(tiff, (int)offset, littleEndian);
        int pos = (int)offset + 2;
        for (int i = 0; i < count; i++)
        {
            if (pos + 12 > tiff.Length) break;
            ushort tag = ReadU16(tiff, pos, littleEndian);
            ushort type = ReadU16(tiff, pos + 2, littleEndian);
            uint valCount = ReadU32(tiff, pos + 4, littleEndian);
            int unitSize = TiffTypeSize(type);
            long byteLenLong = (long)valCount * unitSize;

            if (unitSize > 0 && byteLenLong >= 0 && byteLenLong <= 1024 * 1024)
            {
                int byteLen = (int)byteLenLong;
                byte[] raw;
                if (byteLen <= 4)
                {
                    raw = tiff.AsSpan(pos + 8, byteLen).ToArray();
                }
                else
                {
                    uint valOffset = ReadU32(tiff, pos + 8, littleEndian);
                    if (valOffset + (long)byteLen <= tiff.Length)
                        raw = tiff.AsSpan((int)valOffset, byteLen).ToArray();
                    else
                        raw = Array.Empty<byte>();
                }
                if (raw.Length == byteLen)
                    list.Add(new TiffEntry(tag, type, valCount, raw));
            }
            pos += 12;
        }

        uint nextIfd = pos + 4 <= tiff.Length ? ReadU32(tiff, pos, littleEndian) : 0;
        return (list, nextIfd);
    }

    private static uint MeasureIfdSize(List<TiffEntry> entries)
    {
        uint tableSize = (uint)(2 + entries.Count * 12 + 4);
        uint extraSize = 0;
        foreach (var e in entries)
        {
            if (e.RawBytes.Length > 4)
            {
                uint padded = (uint)e.RawBytes.Length + ((uint)e.RawBytes.Length & 1u);
                extraSize += padded;
            }
        }
        return tableSize + extraSize;
    }

    private static void WriteIfd(Stream ms, List<TiffEntry> entries, uint ifdStartOffset, uint nextIfdOffset, bool littleEndian)
    {
        var sorted = entries.OrderBy(e => e.Tag).ToList();
        uint tableSize = (uint)(2 + sorted.Count * 12 + 4);
        uint dataCursor = ifdStartOffset + tableSize;

        using var outOfLine = new MemoryStream();
        Span<byte> buf2 = stackalloc byte[2];
        Span<byte> buf4 = stackalloc byte[4];

        WriteU16(buf2, 0, (ushort)sorted.Count, littleEndian);
        ms.Write(buf2);

        foreach (var entry in sorted)
        {
            WriteU16(buf2, 0, entry.Tag, littleEndian);
            ms.Write(buf2);
            WriteU16(buf2, 0, entry.Type, littleEndian);
            ms.Write(buf2);
            WriteU32(buf4, 0, entry.Count, littleEndian);
            ms.Write(buf4);

            if (entry.RawBytes.Length <= 4)
            {
                buf4.Clear();
                entry.RawBytes.CopyTo(buf4);
                ms.Write(buf4);
            }
            else
            {
                WriteU32(buf4, 0, dataCursor, littleEndian);
                ms.Write(buf4);
                outOfLine.Write(entry.RawBytes);
                if ((entry.RawBytes.Length & 1) == 1) outOfLine.WriteByte(0);
                dataCursor += (uint)entry.RawBytes.Length + ((uint)entry.RawBytes.Length & 1u);
            }
        }

        WriteU32(buf4, 0, nextIfdOffset, littleEndian);
        ms.Write(buf4);
        outOfLine.Position = 0;
        outOfLine.CopyTo(ms);
    }

    private static JsonNode DecodeTiffValue(TiffEntry entry, bool littleEndian)
    {
        var raw = entry.RawBytes;
        if (entry.Type == 2) // ASCII
            return JsonValue.Create(Encoding.UTF8.GetString(raw).TrimEnd('\0'));

        if (entry.Type == 3 && entry.Count == 1 && raw.Length >= 2) // SHORT
            return JsonValue.Create(ReadU16(raw, 0, littleEndian));

        if (entry.Type == 4 && entry.Count == 1 && raw.Length >= 4) // LONG
            return JsonValue.Create(ReadU32(raw, 0, littleEndian));

        if (entry.Type == 5 && raw.Length >= 8) // RATIONAL
        {
            var vals = new List<double>();
            for (int i = 0; i + 8 <= raw.Length; i += 8)
            {
                uint num = ReadU32(raw, i, littleEndian);
                uint den = ReadU32(raw, i + 4, littleEndian);
                vals.Add(den == 0 ? 0 : Math.Round((double)num / den, 6));
            }
            return vals.Count == 1 ? JsonValue.Create(vals[0]) : JsonValue.Create(string.Join(", ", vals));
        }

        if (entry.Type == 10 && raw.Length >= 8) // SRATIONAL
        {
            int num = (int)ReadU32(raw, 0, littleEndian);
            int den = (int)ReadU32(raw, 4, littleEndian);
            return JsonValue.Create(den == 0 ? 0 : Math.Round((double)num / den, 6));
        }

        if (entry.Tag == 0x9286 && raw.Length > 8) // UserComment
        {
            var text = Encoding.UTF8.GetString(raw[8..]).TrimEnd('\0');
            return JsonValue.Create(text);
        }

        if (entry.Type == 7 && raw.Length <= 16) // Small UNDEFINED (e.g. ExifVersion "0232")
        {
            var ascii = Encoding.ASCII.GetString(raw).TrimEnd('\0');
            if (ascii.All(c => c >= 32 && c < 127))
                return JsonValue.Create(ascii);
        }

        return JsonValue.Create($"({raw.Length} bytes)");
    }

    private static int TiffTypeSize(ushort type) => type switch
    {
        1 or 2 or 6 or 7 => 1,
        3 or 8 => 2,
        4 or 9 or 11 or 13 => 4,
        5 or 10 or 12 => 8,
        _ => 0
    };

    private static ushort ReadU16(ReadOnlySpan<byte> s, int offset, bool le) =>
        le ? BinaryPrimitives.ReadUInt16LittleEndian(s.Slice(offset, 2))
           : BinaryPrimitives.ReadUInt16BigEndian(s.Slice(offset, 2));

    private static uint ReadU32(ReadOnlySpan<byte> s, int offset, bool le) =>
        le ? BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(offset, 4))
           : BinaryPrimitives.ReadUInt32BigEndian(s.Slice(offset, 4));

    private static void WriteU16(Span<byte> s, int offset, ushort val, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt16LittleEndian(s.Slice(offset, 2), val);
        else BinaryPrimitives.WriteUInt16BigEndian(s.Slice(offset, 2), val);
    }

    private static void WriteU32(Span<byte> s, int offset, uint val, bool le)
    {
        if (le) BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(offset, 4), val);
        else BinaryPrimitives.WriteUInt32BigEndian(s.Slice(offset, 4), val);
    }
    #endregion

    #region XMP XML Reader & Selective Filter
    private static void ParseXmp(string xml, JsonObject meta)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            foreach (var desc in doc.Descendants().Where(e => e.Name.LocalName == "Description"))
            {
                foreach (var attr in desc.Attributes().Where(a => !a.IsNamespaceDeclaration && a.Name.LocalName != "about"))
                {
                    var prefix = desc.GetPrefixOfNamespace(attr.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{attr.Name.LocalName}" : $"XMP-{prefix}:{attr.Name.LocalName}";
                    meta[key] = attr.Value;
                }

                foreach (var el in desc.Elements())
                {
                    var prefix = desc.GetPrefixOfNamespace(el.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{el.Name.LocalName}" : $"XMP-{prefix}:{el.Name.LocalName}";
                    var leafValues = el.Descendants().Where(d => !d.HasElements && !string.IsNullOrWhiteSpace(d.Value))
                        .Select(d => d.Value.Trim()).ToList();
                    meta[key] = leafValues.Count > 0 ? string.Join(", ", leafValues) : el.Value.Trim();
                }
            }
        }
        catch { }
    }

    private static string? FilterXmp(string xml, Dictionary<string, MetaAction> actions)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var descriptions = doc.Descendants().Where(e => e.Name.LocalName == "Description").ToList();
            if (descriptions.Count == 0) return null;

            bool anyKept = false;
            foreach (var desc in descriptions)
            {
                foreach (var attr in desc.Attributes().Where(a => !a.IsNamespaceDeclaration && a.Name.LocalName != "about").ToList())
                {
                    var prefix = desc.GetPrefixOfNamespace(attr.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{attr.Name.LocalName}" : $"XMP-{prefix}:{attr.Name.LocalName}";
                    if (!ShouldKeep(actions, key) && !ShouldKeep(actions, attr.Name.LocalName))
                        attr.Remove();
                    else
                        anyKept = true;
                }

                foreach (var el in desc.Elements().ToList())
                {
                    var prefix = desc.GetPrefixOfNamespace(el.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{el.Name.LocalName}" : $"XMP-{prefix}:{el.Name.LocalName}";
                    if (!ShouldKeep(actions, key) && !ShouldKeep(actions, el.Name.LocalName))
                        el.Remove();
                    else
                        anyKept = true;
                }
            }

            return anyKept ? doc.ToString(SaveOptions.DisableFormatting) : null;
        }
        catch
        {
            return null;
        }
    }
    #endregion
}
