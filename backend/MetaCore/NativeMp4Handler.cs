using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Pure-C# volatile in-memory ISO-BMFF (.mp4, .mov, .m4a) atom inspector and selective sanitizer.
/// Strips or normalizes QuickTime/iTunes metadata boxes (udta/meta) while preserving display orientation
/// matrices (tkhd rotation), media durations, codec descriptors, and recalculated stco/co64 chunk offsets.
/// </summary>
public static class NativeMp4Handler
{
    private static readonly DateTime MacEpoch = new(1904, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private static readonly Dictionary<string, string> IlstAtomTagMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["\u00a9nam"] = "Title",
        ["\u00a9ART"] = "Artist",
        ["\u00a9day"] = "ContentCreateDate",
        ["\u00a9too"] = "WritingApplication",
        ["\u00a9cmt"] = "Comment",
        ["\u00a9wrt"] = "Author",
        ["\u00a9xyz"] = "GPSCoordinates",
        ["cprt"] = "Copyright"
    };

    public static void ExtractMetadata(byte[] bytes, JsonObject meta, string ext)
    {
        meta["FileType"] = ext.TrimStart('.').ToUpperInvariant();
        meta["FileTypeExtension"] = ext.TrimStart('.');
        meta["MIMEType"] = ext switch
        {
            ".mov" => "video/quicktime",
            ".m4a" => "audio/mp4",
            _ => "video/mp4"
        };

        WalkBoxes(bytes, 0, bytes.Length, (type, start, headerSize, size) =>
        {
            var contentStart = start + headerSize;
            var contentLen = (int)(size - headerSize);
            if (contentLen <= 0 || contentStart + contentLen > bytes.Length) return;

            if (type is "moov" or "trak" or "mdia" or "minf" or "stbl")
            {
                WalkChildren(bytes, contentStart, contentLen, meta);
            }
            else if (type == "udta")
            {
                ExtractUdta(bytes.AsSpan(contentStart, contentLen), meta);
            }
            else if (type == "meta")
            {
                ExtractMetaBox(bytes.AsSpan(contentStart, contentLen), meta);
            }
        });
    }

    private static void WalkChildren(byte[] bytes, int start, int len, JsonObject meta)
    {
        WalkBoxes(bytes, start, start + len, (type, boxStart, headerSize, boxSize) =>
        {
            var cs = boxStart + headerSize;
            var cl = (int)(boxSize - headerSize);
            if (cl <= 0 || cs + cl > bytes.Length) return;
            var span = bytes.AsSpan(cs, cl);

            switch (type)
            {
                case "trak" or "mdia" or "minf" or "stbl":
                    WalkChildren(bytes, cs, cl, meta);
                    break;
                case "mvhd":
                    ExtractMvhd(span, meta);
                    break;
                case "tkhd":
                    ExtractTkhd(span, meta);
                    break;
                case "mdhd":
                    ExtractMdhd(span, meta);
                    break;
                case "stsd":
                    ExtractStsd(span, meta);
                    break;
                case "udta":
                    ExtractUdta(span, meta);
                    break;
                case "meta":
                    ExtractMetaBox(span, meta);
                    break;
            }
        });
    }

    public static byte[] SanitizeBytes(
        byte[] bytes,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        // Locate top-level boxes; track moov position relative to mdat so stco/co64 offsets stay valid
        var topBoxes = new List<(string Type, int Start, int Size)>();
        int pos = 0;
        while (TryReadBoxHeader(bytes, pos, bytes.Length, out var type, out _, out var size))
        {
            topBoxes.Add((type, pos, (int)size));
            pos += (int)size;
        }

        if (topBoxes.Count == 0) return bytes;

        int moovOldOffset = -1;
        int moovOldLen = 0;
        int moovNewLen = 0;
        int mdatOldOffset = int.MaxValue;

        foreach (var b in topBoxes)
        {
            if (b.Type == "moov") { moovOldOffset = b.Start; moovOldLen = b.Size; }
            if (b.Type == "mdat" && b.Start < mdatOldOffset) mdatOldOffset = b.Start;
        }

        byte[]? rebuiltMoov = null;
        if (moovOldOffset >= 0)
        {
            var moovHeaderLen = (bytes[moovOldOffset] == 0 && moovOldOffset + 16 <= bytes.Length &&
                                 BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(moovOldOffset, 4)) == 1) ? 16 : 8;
            rebuiltMoov = RebuildContainerBox(
                "moov",
                bytes.AsSpan(moovOldOffset + moovHeaderLen, moovOldLen - moovHeaderLen),
                actions,
                normalizedValues);
            moovNewLen = rebuiltMoov.Length;
        }

        long chunkOffsetDelta = (moovOldOffset >= 0 && moovOldOffset < mdatOldOffset)
            ? (long)moovNewLen - moovOldLen
            : 0L;

        if (rebuiltMoov != null && chunkOffsetDelta != 0)
            AdjustChunkOffsetsInMoov(rebuiltMoov, chunkOffsetDelta);

        using var outMs = new MemoryStream(bytes.Length);
        foreach (var b in topBoxes)
        {
            if (b.Type == "moov" && rebuiltMoov != null)
                outMs.Write(rebuiltMoov, 0, rebuiltMoov.Length);
            else if (b.Type is "udta" or "meta" && !ShouldKeepAnyMeta(actions))
                continue;
            else
                outMs.Write(bytes, b.Start, b.Size);
        }

        return outMs.ToArray();
    }

    private static byte[] RebuildContainerBox(
        string containerType,
        ReadOnlySpan<byte> children,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        using var inner = new MemoryStream();
        int p = 0;
        while (TryReadBoxHeader(children, p, children.Length, out var childType, out int hdrLen, out long boxSize))
        {
            var payload = children.Slice(p + hdrLen, (int)boxSize - hdrLen);
            if (childType is "udta" or "meta")
            {
                if (ShouldKeepAnyMeta(actions))
                {
                    WriteFullBox(inner, childType, payload);
                }
            }
            else if (childType is "trak" or "mdia" or "minf" or "stbl")
            {
                var nested = RebuildContainerBox(childType, payload, actions, normalizedValues);
                inner.Write(nested, 0, nested.Length);
            }
            else if (childType is "mvhd" or "tkhd" or "mdhd")
            {
                var sanitizedTimeBox = SanitizeTimeBox(childType, payload.ToArray(), actions, normalizedValues);
                WriteFullBox(inner, childType, sanitizedTimeBox);
            }
            else
            {
                WriteFullBox(inner, childType, payload);
            }

            p += (int)boxSize;
        }

        var body = inner.ToArray();
        var result = new byte[8 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(0, 4), (uint)result.Length);
        Encoding.Latin1.GetBytes(containerType, result.AsSpan(4, 4));
        body.CopyTo(result, 8);
        return result;
    }

    private static byte[] SanitizeTimeBox(
        string boxType,
        byte[] payload,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        if (payload.Length < 12) return payload;
        byte version = payload[0];
        bool stripCreate = actions.TryGetValue("CreateDate", out var ca) && ca != MetaAction.Keep;
        bool stripMod = actions.TryGetValue("ModifyDate", out var ma) && ma != MetaAction.Keep;

        uint newCreate = 0, newMod = 0;
        if (ca == MetaAction.Normalize && normalizedValues?.TryGetValue("CreateDate", out var nc) == true)
            newCreate = ParseToMacEpochSeconds(nc);
        if (ma == MetaAction.Normalize && normalizedValues?.TryGetValue("ModifyDate", out var nm) == true)
            newMod = ParseToMacEpochSeconds(nm);

        if (version == 0 && payload.Length >= 12)
        {
            if (stripCreate) BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4, 4), newCreate);
            if (stripMod) BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(8, 4), newMod);
        }
        else if (version == 1 && payload.Length >= 20)
        {
            if (stripCreate) BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(4, 8), newCreate);
            if (stripMod) BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(12, 8), newMod);
        }

        // Explicitly never alter tkhd rotation matrix or track geometry!
        _ = boxType;
        return payload;
    }

    private static void AdjustChunkOffsetsInMoov(byte[] moovBytes, long delta)
    {
        AdjustRecursive(moovBytes, 8, moovBytes.Length, delta);
    }

    private static void AdjustRecursive(byte[] buf, int start, int end, long delta)
    {
        int p = start;
        while (TryReadBoxHeader(buf, p, end, out var type, out int hdrLen, out long size))
        {
            int cs = p + hdrLen;
            int ce = p + (int)size;
            if (type is "trak" or "mdia" or "minf" or "stbl")
            {
                AdjustRecursive(buf, cs, ce, delta);
            }
            else if (type == "stco" && cs + 8 <= ce)
            {
                uint count = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(cs + 4, 4));
                for (uint i = 0; i < count && cs + 8 + (int)(i + 1) * 4 <= ce; i++)
                {
                    int offPos = cs + 8 + (int)i * 4;
                    long cur = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(offPos, 4));
                    BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(offPos, 4), (uint)Math.Max(0, cur + delta));
                }
            }
            else if (type == "co64" && cs + 8 <= ce)
            {
                uint count = BinaryPrimitives.ReadUInt32BigEndian(buf.AsSpan(cs + 4, 4));
                for (uint i = 0; i < count && cs + 8 + (int)(i + 1) * 8 <= ce; i++)
                {
                    int offPos = cs + 8 + (int)i * 8;
                    long cur = (long)BinaryPrimitives.ReadUInt64BigEndian(buf.AsSpan(offPos, 8));
                    BinaryPrimitives.WriteUInt64BigEndian(buf.AsSpan(offPos, 8), (ulong)Math.Max(0, cur + delta));
                }
            }

            p += (int)size;
        }
    }

    private static void ExtractMvhd(ReadOnlySpan<byte> data, JsonObject meta)
    {
        if (data.Length < 20) return;
        byte version = data[0];
        uint cTime, mTime, timescale, dur;
        if (version == 0 && data.Length >= 20)
        {
            cTime = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(4, 4));
            mTime = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(8, 4));
            timescale = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(12, 4));
            dur = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(16, 4));
        }
        else if (version == 1 && data.Length >= 32)
        {
            cTime = (uint)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(4, 8));
            mTime = (uint)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(12, 8));
            timescale = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(20, 4));
            dur = (uint)BinaryPrimitives.ReadUInt64BigEndian(data.Slice(24, 8));
        }
        else return;

        if (cTime > 0) meta["CreateDate"] = MacEpoch.AddSeconds(cTime).ToString("yyyy:MM:dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (mTime > 0) meta["ModifyDate"] = MacEpoch.AddSeconds(mTime).ToString("yyyy:MM:dd HH:mm:ss", CultureInfo.InvariantCulture);
        if (timescale > 0) meta["Duration"] = Math.Round((double)dur / timescale, 2);
    }

    private static void ExtractTkhd(ReadOnlySpan<byte> data, JsonObject meta)
    {
        if (data.Length < 84) return;
        byte version = data[0];
        int matrixOffset = version == 0 ? 40 : 52;
        if (data.Length < matrixOffset + 44) return;

        // Transformation matrix [a, b, u, c, d, v, ...] encoded as 16.16 fixed-point
        double a = BinaryPrimitives.ReadInt32BigEndian(data.Slice(matrixOffset, 4)) / 65536.0;
        double b = BinaryPrimitives.ReadInt32BigEndian(data.Slice(matrixOffset + 4, 4)) / 65536.0;
        int rot = (int)Math.Round(Math.Atan2(b, a) * 180.0 / Math.PI);
        if (rot < 0) rot += 360;
        meta["Rotate"] = rot;

        uint w = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(matrixOffset + 36, 4)) >> 16;
        uint h = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(matrixOffset + 40, 4)) >> 16;
        if (w > 0 && h > 0)
        {
            meta["ImageWidth"] = w;
            meta["ImageHeight"] = h;
        }
    }

    private static void ExtractMdhd(ReadOnlySpan<byte> data, JsonObject meta)
    {
        if (data.Length < 20) return;
        uint timescale = data[0] == 0
            ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(12, 4))
            : data.Length >= 24 ? BinaryPrimitives.ReadUInt32BigEndian(data.Slice(20, 4)) : 0;
        if (timescale > 0)
            meta["SampleRate"] = timescale;
    }

    private static void ExtractStsd(ReadOnlySpan<byte> data, JsonObject meta)
    {
        if (data.Length < 16) return;
        var codec = Encoding.Latin1.GetString(data.Slice(12, 4)).Trim();
        if (!string.IsNullOrEmpty(codec))
        {
            if (codec is "mp4a" or "aac " or "ac-3" or "alac")
                meta["AudioCodec"] = codec;
            else
                meta["VideoCodec"] = codec;
        }
    }

    private static void ExtractUdta(ReadOnlySpan<byte> span, JsonObject meta)
    {
        var arr = span.ToArray();
        WalkBoxes(arr, 0, arr.Length, (type, start, hdrLen, size) =>
        {
            var cs = start + hdrLen;
            var cl = (int)(size - hdrLen);
            if (cl <= 0 || cs + cl > arr.Length) return;
            var payload = arr.AsSpan(cs, cl);

            if (type == "meta")
            {
                ExtractMetaBox(payload, meta);
            }
            else if (type == "\u00a9xyz" && payload.Length >= 4)
            {
                int textLen = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                var text = Encoding.UTF8.GetString(payload.Slice(4, Math.Min(textLen, payload.Length - 4)));
                ParseIso6709(text, meta);
            }
            else if (IlstAtomTagMap.TryGetValue(type, out var tagName) && payload.Length >= 4)
            {
                int textLen = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                var val = Encoding.UTF8.GetString(payload.Slice(4, Math.Min(textLen, payload.Length - 4)));
                if (!string.IsNullOrWhiteSpace(val))
                    meta[tagName] = val.Trim('\0', ' ');
            }
        });
    }

    private static void ExtractMetaBox(ReadOnlySpan<byte> data, JsonObject meta)
    {
        // FullBox starts with 4 bytes version/flags unless Apple mdta omits FullBox header (detect hdlr/keys/ilst at 0 or 4)
        int offset = (data.Length >= 12 && (Encoding.Latin1.GetString(data.Slice(8, 4)) is "hdlr" or "keys" or "ilst")) ? 4 : 0;
        var arr = data[offset..].ToArray();
        var keys = new List<string>();

        WalkBoxes(arr, 0, arr.Length, (type, start, hdrLen, size) =>
        {
            var cs = start + hdrLen;
            var cl = (int)(size - hdrLen);
            if (cl <= 0 || cs + cl > arr.Length) return;
            var p = arr.AsSpan(cs, cl);

            if (type == "keys" && p.Length >= 8)
            {
                uint count = BinaryPrimitives.ReadUInt32BigEndian(p.Slice(4, 4));
                int kp = 8;
                for (uint i = 0; i < count && kp + 8 <= p.Length; i++)
                {
                    int ks = (int)BinaryPrimitives.ReadUInt32BigEndian(p.Slice(kp, 4));
                    if (ks < 8 || kp + ks > p.Length) break;
                    keys.Add(Encoding.UTF8.GetString(p.Slice(kp + 8, ks - 8)));
                    kp += ks;
                }
            }
            else if (type == "ilst")
            {
                ExtractIlst(p, keys, meta);
            }
        });
    }

    private static void ExtractIlst(ReadOnlySpan<byte> ilst, List<string> keys, JsonObject meta)
    {
        int p = 0;
        while (TryReadBoxHeader(ilst, p, ilst.Length, out var itemType, out int hdrLen, out long size))
        {
            var payload = ilst.Slice(p + hdrLen, (int)size - hdrLen);
            string tagName = itemType;
            uint idx = BinaryPrimitives.ReadUInt32BigEndian(ilst.Slice(p + 4, 4));
            if (idx >= 1 && idx <= keys.Count)
            {
                var k = keys[(int)idx - 1];
                tagName = k.Split('.')[^1] switch
                {
                    "ISO6709" => "GPSCoordinates",
                    "make" => "Make",
                    "model" => "Model",
                    "software" => "Software",
                    "creationdate" => "CreateDate",
                    _ => k
                };
            }
            else if (IlstAtomTagMap.TryGetValue(itemType, out var mapped))
            {
                tagName = mapped;
            }

            if (payload.Length > 16 && Encoding.Latin1.GetString(payload.Slice(4, 4)) == "data")
            {
                var str = Encoding.UTF8.GetString(payload[16..]).Trim('\0', ' ');
                if (!string.IsNullOrEmpty(str))
                {
                    if (tagName == "GPSCoordinates")
                        ParseIso6709(str, meta);
                    else
                        meta[tagName] = str;
                }
            }

            p += (int)size;
        }
    }

    private static void ParseIso6709(string text, JsonObject meta)
    {
        meta["GPSCoordinates"] = text;
        var m = Regex.Match(text, @"([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)");
        if (m.Success)
        {
            meta["GPSLatitude"] = m.Groups[1].Value;
            meta["GPSLongitude"] = m.Groups[2].Value;
        }
    }

    private static bool ShouldKeepAnyMeta(Dictionary<string, MetaAction> actions) =>
        actions.Any(kvp => (kvp.Key.Contains("Title", StringComparison.OrdinalIgnoreCase) ||
                            kvp.Key.Contains("Copyright", StringComparison.OrdinalIgnoreCase)) &&
                           kvp.Value == MetaAction.Keep);

    private static uint ParseToMacEpochSeconds(string s)
    {
        if (TamperDetectionService.TryParseMetadataDateTime(s, out var dt))
        {
            var utc = dt.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(dt, DateTimeKind.Utc)
                : dt.ToUniversalTime();
            return (uint)Math.Max(0, (utc - MacEpoch).TotalSeconds);
        }
        return 0;
    }

    private static void WalkBoxes(byte[] buf, int start, int end, Action<string, int, int, long> visitor)
    {
        int p = start;
        while (TryReadBoxHeader(buf, p, end, out var type, out int hdrLen, out long size))
        {
            visitor(type, p, hdrLen, size);
            p += (int)size;
        }
    }

    private static bool TryReadBoxHeader(ReadOnlySpan<byte> buf, int pos, int end, out string type, out int headerLen, out long boxSize)
    {
        type = string.Empty;
        headerLen = 0;
        boxSize = 0;
        if (pos + 8 > end) return false;

        uint sz32 = BinaryPrimitives.ReadUInt32BigEndian(buf.Slice(pos, 4));
        type = Encoding.Latin1.GetString(buf.Slice(pos + 4, 4));
        if (sz32 == 1)
        {
            if (pos + 16 > end) return false;
            boxSize = (long)BinaryPrimitives.ReadUInt64BigEndian(buf.Slice(pos + 8, 8));
            headerLen = 16;
        }
        else if (sz32 == 0)
        {
            boxSize = end - pos;
            headerLen = 8;
        }
        else
        {
            boxSize = sz32;
            headerLen = 8;
        }

        return boxSize >= headerLen && pos + boxSize <= end;
    }

    private static void WriteFullBox(Stream ms, string type, ReadOnlySpan<byte> payload)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)(8 + payload.Length));
        ms.Write(len);
        ms.Write(Encoding.Latin1.GetBytes(type.PadRight(4)[..4]));
        ms.Write(payload);
    }
}
