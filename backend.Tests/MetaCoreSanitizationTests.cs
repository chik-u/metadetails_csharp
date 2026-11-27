using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using MetaDetective.Api.MetaCore;
using Xunit;

namespace MetaDetective.Tests;

public class MetaCoreSanitizationTests
{
    private readonly MetaCoreEngine _engine = new();

    [Fact]
    public void MetaCoreEngine_AssignsPrioritiesAndPreservesRequiredAndLow()
    {
        var metadata = new JsonObject
        {
            ["ImageWidth"] = 1920,
            ["Orientation"] = 1,
            ["ExposureTime"] = 0.01,
            ["ISO"] = 200,
            ["FocalLength"] = 35,
            ["Make"] = "Canon",
            ["DateTimeOriginal"] = "2026:05:01 12:30:00",
            ["GPSLatitude"] = "37.7749",
            ["Artist"] = "Jane Doe",
            ["SerialNumber"] = "SN-999123"
        };

        var report = _engine.AnalyzeMetadata(metadata);

        Assert.Equal("Critical", report.RiskLevel);
        Assert.Equal(2, report.RequiredCount);
        Assert.Equal(3, report.LowPriorityCount);
        Assert.Equal(2, report.HighPriorityCount);
        Assert.Equal(3, report.CriticalPriorityCount);
        Assert.Equal(5, report.SensitiveCount);
        Assert.Equal(5, report.KeptCount);
        Assert.Equal(5, report.RemovedCount);

        // Highest priority / sensitivity surfaces first
        Assert.Equal(MetaPriority.Critical, report.Details[0].Priority);
        Assert.Equal(MetaPriority.Required, report.Details[^1].Priority);

        Assert.Contains("Orientation", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ExposureTime", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ISO", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("FocalLength", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);

        Assert.DoesNotContain("GPSLatitude", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Artist", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Make", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("DateTimeOriginal", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("SerialNumber", report.WritablePreserveTags, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void MetaCoreEngine_RespectsPolicyOptionsAndOverrides()
    {
        var metadata = new JsonObject
        {
            ["Orientation"] = 1,
            ["ISO"] = 400,
            ["Software"] = "Adobe Lightroom",
            ["CustomTag"] = "custom-val"
        };

        var strictOpts = new MetaSanitizeOptions
        {
            KeepLowPriority = false,
            StrictMode = true,
            KeepTags = ["Software"]
        };

        var report = _engine.AnalyzeMetadata(metadata, strictOpts);

        var orientation = report.Details.Single(d => d.Key == "Orientation");
        var iso = report.Details.Single(d => d.Key == "ISO");
        var software = report.Details.Single(d => d.Key == "Software");
        var custom = report.Details.Single(d => d.Key == "CustomTag");

        Assert.Equal(MetaAction.Keep, orientation.Action);
        Assert.Equal(MetaAction.Remove, iso.Action);
        Assert.Equal(MetaAction.Keep, software.Action);
        Assert.Equal(MetaAction.Remove, custom.Action);
    }

    [Fact]
    public async Task SanitizeJpeg_RemovesSensitiveMetadata_KeepsRequiredAndLowPriority()
    {
        var jpegBytes = BuildTestJpegWithFullMetadata();
        var tempIn = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.jpg");
        try
        {
            await File.WriteAllBytesAsync(tempIn, jpegBytes);
            var extractor = new MetadataExtractorService();
            var sanitizer = new FileSanitizerService(_engine, extractor);

            var (result, sanitizedBytes) = await sanitizer.SanitizeFileAsync(tempIn, "photo.jpg", "image/jpeg");

            Assert.True(sanitizedBytes.Length > 0);
            Assert.Equal(0xFF, sanitizedBytes[0]);
            Assert.Equal(0xD8, sanitizedBytes[1]);
            Assert.Equal(0xFF, sanitizedBytes[^2]);
            Assert.Equal(0xD9, sanitizedBytes[^1]);

            // All embedded sensitive fields must be gone after sanitization
            Assert.Empty(result.RemainingSensitiveFields);
            Assert.Equal("Low", result.AfterReport.RiskLevel);

            var afterKeys = result.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Sensitive fields removed
            Assert.DoesNotContain("Artist", afterKeys);
            Assert.DoesNotContain("Make", afterKeys);
            Assert.DoesNotContain("Model", afterKeys);
            Assert.DoesNotContain("Software", afterKeys);
            Assert.DoesNotContain("DateTimeOriginal", afterKeys);
            Assert.DoesNotContain("SerialNumber", afterKeys);
            Assert.DoesNotContain("UserComment", afterKeys);
            Assert.DoesNotContain("MakerNotes", afterKeys);
            Assert.DoesNotContain("ThumbnailImage", afterKeys);
            Assert.DoesNotContain("GPSLatitude", afterKeys);
            Assert.DoesNotContain("GPSLongitude", afterKeys);
            Assert.DoesNotContain("Comment", afterKeys);
            Assert.DoesNotContain("IPTCData", afterKeys);
            Assert.DoesNotContain("creator", afterKeys);

            // Required & Low-priority fields preserved
            Assert.Contains("ImageWidth", afterKeys);
            Assert.Contains("ImageHeight", afterKeys);
            Assert.Contains("JFIFVersion", afterKeys);
            Assert.Contains("Orientation", afterKeys);
            Assert.Contains("XResolution", afterKeys);
            Assert.Contains("ExposureTime", afterKeys);
            Assert.Contains("FNumber", afterKeys);
            Assert.Contains("ISO", afterKeys);
            Assert.Contains("FocalLength", afterKeys);
            Assert.Contains("ExifVersion", afterKeys);
        }
        finally
        {
            if (File.Exists(tempIn)) File.Delete(tempIn);
        }
    }

    [Fact]
    public async Task SanitizeJpeg_WhenKeepLowPriorityDisabled_KeepsOnlyRequired()
    {
        var jpegBytes = BuildTestJpegWithFullMetadata();
        var tempIn = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.jpg");
        try
        {
            await File.WriteAllBytesAsync(tempIn, jpegBytes);
            var sanitizer = new FileSanitizerService(_engine, new MetadataExtractorService());

            var (result, _) = await sanitizer.SanitizeFileAsync(
                tempIn,
                "photo.jpg",
                "image/jpeg",
                new MetaSanitizeOptions { KeepRequired = true, KeepLowPriority = false });

            var afterKeys = result.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

            Assert.Empty(result.RemainingSensitiveFields);
            Assert.DoesNotContain("ExposureTime", afterKeys);
            Assert.DoesNotContain("ISO", afterKeys);
            Assert.DoesNotContain("FocalLength", afterKeys);
            Assert.Contains("Orientation", afterKeys);
            Assert.Contains("XResolution", afterKeys);
            Assert.Contains("ImageWidth", afterKeys);
        }
        finally
        {
            if (File.Exists(tempIn)) File.Delete(tempIn);
        }
    }

    [Fact]
    public async Task SanitizePng_RemovesSensitiveChunks_KeepsStructuralAndExifLowPriority()
    {
        var pngBytes = BuildTestPngWithMetadata();
        var tempIn = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.png");
        try
        {
            await File.WriteAllBytesAsync(tempIn, pngBytes);
            var sanitizer = new FileSanitizerService(_engine, new MetadataExtractorService());

            var (result, sanitizedBytes) = await sanitizer.SanitizeFileAsync(tempIn, "diagram.png", "image/png");

            Assert.Empty(result.RemainingSensitiveFields);
            Assert.Equal([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], sanitizedBytes[..8]);

            var afterKeys = result.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Sensitive chunks removed
            Assert.DoesNotContain("Author", afterKeys);
            Assert.DoesNotContain("Software", afterKeys);
            Assert.DoesNotContain("ModifyDate", afterKeys);
            Assert.DoesNotContain("Artist", afterKeys);
            Assert.DoesNotContain("DateTimeOriginal", afterKeys);

            // Structural & low priority kept
            Assert.Contains("ImageWidth", afterKeys);
            Assert.Contains("ImageHeight", afterKeys);
            Assert.Contains("PixelsPerUnitX", afterKeys);
            Assert.Contains("SRGBRendering", afterKeys);
            Assert.Contains("Orientation", afterKeys);
            Assert.Contains("ISO", afterKeys);
        }
        finally
        {
            if (File.Exists(tempIn)) File.Delete(tempIn);
        }
    }

    [Fact]
    public async Task SanitizeSvgAndWav_StripsSensitiveMetadata_KeepsRequiredFields()
    {
        var svgContent = """
            <svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" width="200" height="100" inkscape:version="1.3">
              <!-- Created by Jane on WORKSTATION-42 -->
              <metadata><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Jane</dc:creator></rdf:RDF></metadata>
              <rect width="200" height="100" fill="blue" />
            </svg>
            """;

        var tempSvg = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.svg");
        var tempWav = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.wav");
        try
        {
            await File.WriteAllTextAsync(tempSvg, svgContent, Encoding.UTF8);
            await File.WriteAllBytesAsync(tempWav, BuildTestWavWithInfo());

            var sanitizer = new FileSanitizerService(_engine, new MetadataExtractorService());

            var (svgRes, svgOut) = await sanitizer.SanitizeFileAsync(tempSvg, "vector.svg", "image/svg+xml");
            var svgText = Encoding.UTF8.GetString(svgOut);
            Assert.Empty(svgRes.RemainingSensitiveFields);
            Assert.DoesNotContain("WORKSTATION-42", svgText);
            Assert.DoesNotContain("inkscape", svgText);
            Assert.DoesNotContain("<metadata", svgText);
            Assert.Contains("width=\"200\"", svgText);
            Assert.Contains("<rect", svgText);

            var (wavRes, _) = await sanitizer.SanitizeFileAsync(tempWav, "clip.wav", "audio/wav");
            Assert.Empty(wavRes.RemainingSensitiveFields);
            var wavKeys = wavRes.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.DoesNotContain("Artist", wavKeys);
            Assert.DoesNotContain("Software", wavKeys);
            Assert.Contains("SampleRate", wavKeys);
            Assert.Contains("AudioChannels", wavKeys);
        }
        finally
        {
            if (File.Exists(tempSvg)) File.Delete(tempSvg);
            if (File.Exists(tempWav)) File.Delete(tempWav);
        }
    }

    [Fact]
    public async Task SanitizeGifAndWebp_StripsCommentsAndSensitiveExif_KeepsRequiredAndLow()
    {
        var tempGif = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.gif");
        var tempWebp = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.webp");
        try
        {
            await File.WriteAllBytesAsync(tempGif, BuildTestGifWithComment());
            await File.WriteAllBytesAsync(tempWebp, BuildTestWebpWithExif());

            var sanitizer = new FileSanitizerService(_engine, new MetadataExtractorService());

            var (gifRes, gifOut) = await sanitizer.SanitizeFileAsync(tempGif, "anim.gif", "image/gif");
            Assert.Empty(gifRes.RemainingSensitiveFields);
            Assert.Equal(0x3B, gifOut[^1]);
            var gifKeys = gifRes.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.DoesNotContain("Comment", gifKeys);
            Assert.Contains("ImageWidth", gifKeys);
            Assert.Contains("ImageHeight", gifKeys);

            var (webpRes, webpOut) = await sanitizer.SanitizeFileAsync(tempWebp, "photo.webp", "image/webp");
            Assert.Empty(webpRes.RemainingSensitiveFields);
            Assert.Equal("RIFF", Encoding.ASCII.GetString(webpOut, 0, 4));
            var webpKeys = webpRes.AfterReport.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.DoesNotContain("Artist", webpKeys);
            Assert.DoesNotContain("GPSLatitude", webpKeys);
            Assert.Contains("ImageWidth", webpKeys);
            Assert.Contains("Orientation", webpKeys);
            Assert.Contains("ISO", webpKeys);
        }
        finally
        {
            if (File.Exists(tempGif)) File.Delete(tempGif);
            if (File.Exists(tempWebp)) File.Delete(tempWebp);
        }
    }

    #region Binary Fixture Builders
    private static byte[] BuildTestJpegWithFullMetadata()
    {
        using var ms = new MemoryStream();
        ms.Write([0xFF, 0xD8]); // SOI

        // APP0 JFIF
        WriteSegment(ms, 0xE0, [.. "JFIF\0"u8, 1, 1, 1, 0, 72, 0, 72, 0, 0]);

        // APP1 EXIF
        var tiff = BuildTestTiffExifBytes();
        var exifPayload = new byte[6 + tiff.Length];
        "Exif\0\0"u8.CopyTo(exifPayload);
        tiff.CopyTo(exifPayload, 6);
        WriteSegment(ms, 0xE1, exifPayload);

        // APP1 XMP
        var xmp = "http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><dc:creator>John Doe</dc:creator><xmp:CreatorTool>SecretTool</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta>";
        WriteSegment(ms, 0xE1, Encoding.UTF8.GetBytes(xmp));

        // APP13 Photoshop/IPTC
        WriteSegment(ms, 0xED, Encoding.ASCII.GetBytes("Photoshop 3.0\08BIM"));

        // COM Comment
        WriteSegment(ms, 0xFE, Encoding.UTF8.GetBytes("Confidential location note"));

        // SOF0 (640x480, 8-bit, 3 components)
        WriteSegment(ms, 0xC0, [8, 0x01, 0xE0, 0x02, 0x80, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

        // Minimal SOS + EOI
        ms.Write([0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0xAA, 0xBB]);
        ms.Write([0xFF, 0xD9]);
        return ms.ToArray();
    }

    private static byte[] BuildTestTiffExifBytes()
    {
        var ifd0 = new List<(ushort Tag, ushort Type, uint Count, byte[] Data)>
        {
            (0x010F, 2, 6, "Canon\0"u8.ToArray()),                         // Make (High)
            (0x0110, 2, 9, "EOS R5\0\0\0"u8.ToArray()),                    // Model (High)
            (0x0112, 3, 1, BitConverter.GetBytes((ushort)1)),              // Orientation (Required)
            (0x011A, 5, 1, Rational(300, 1)),                              // XResolution (Required)
            (0x0131, 2, 10, "Lightroom\0"u8.ToArray()),                    // Software (High)
            (0x013B, 2, 9, "Jane Doe\0"u8.ToArray()),                      // Artist (Critical)
            (0x8298, 2, 10, "2026 Corp\0"u8.ToArray()),                    // Copyright (Critical)
        };

        var exifIfd = new List<(ushort Tag, ushort Type, uint Count, byte[] Data)>
        {
            (0x829A, 5, 1, Rational(1, 125)),                              // ExposureTime (Low)
            (0x829D, 5, 1, Rational(28, 10)),                              // FNumber (Low)
            (0x8827, 3, 1, BitConverter.GetBytes((ushort)100)),            // ISO (Low)
            (0x9000, 7, 4, "0232"u8.ToArray()),                            // ExifVersion (Low)
            (0x9003, 2, 20, "2026:05:01 12:00:00\0"u8.ToArray()),          // DateTimeOriginal (High)
            (0x920A, 5, 1, Rational(50, 1)),                               // FocalLength (Low)
            (0x927C, 7, 6, [1, 2, 3, 4, 5, 6]),                            // MakerNotes (High)
            (0x9286, 7, 15, [.. "ASCII\0\0\0"u8, .. "Secret!"u8]),         // UserComment (Critical)
            (0xA431, 2, 9, "SN123456\0"u8.ToArray()),                      // SerialNumber (Critical)
        };

        var gpsIfd = new List<(ushort Tag, ushort Type, uint Count, byte[] Data)>
        {
            (0x0001, 2, 2, "N\0"u8.ToArray()),                             // GPSLatitudeRef
            (0x0002, 5, 3, [.. Rational(37, 1), .. Rational(46, 1), .. Rational(29, 1)]), // GPSLatitude
            (0x0003, 2, 2, "W\0"u8.ToArray()),                             // GPSLongitudeRef
            (0x0004, 5, 3, [.. Rational(122, 1), .. Rational(25, 1), .. Rational(9, 1)]), // GPSLongitude
        };

        // Add pointer placeholders to IFD0 and compute offsets
        var allIfd0 = new List<(ushort Tag, ushort Type, uint Count, byte[] Data)>(ifd0)
        {
            (0x8769, 4, 1, new byte[4]),
            (0x8825, 4, 1, new byte[4])
        };

        uint ifd0Start = 8;
        uint ifd0Size = MeasureIfd(allIfd0);
        uint exifStart = ifd0Start + ifd0Size;
        uint exifSize = MeasureIfd(exifIfd);
        uint gpsStart = exifStart + exifSize;
        uint gpsSize = MeasureIfd(gpsIfd);
        uint ifd1Start = gpsStart + gpsSize;

        for (int i = 0; i < allIfd0.Count; i++)
        {
            if (allIfd0[i].Tag == 0x8769) allIfd0[i] = (0x8769, 4, 1, BitConverter.GetBytes(exifStart));
            if (allIfd0[i].Tag == 0x8825) allIfd0[i] = (0x8825, 4, 1, BitConverter.GetBytes(gpsStart));
        }

        using var ms = new MemoryStream();
        ms.Write([(byte)'I', (byte)'I', 42, 0, 8, 0, 0, 0]);
        WriteIfd(ms, allIfd0, ifd0Start, ifd1Start);
        WriteIfd(ms, exifIfd, exifStart, 0);
        WriteIfd(ms, gpsIfd, gpsStart, 0);
        // Minimal IFD1 thumbnail entry
        WriteIfd(ms, [(0x0103, 3, 1, BitConverter.GetBytes((ushort)6))], ifd1Start, 0);
        return ms.ToArray();
    }

    private static byte[] BuildTestPngWithMetadata()
    {
        using var ms = new MemoryStream();
        ms.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        // IHDR: 100x80
        var ihdr = new byte[13];
        BinaryPrimitives.WriteUInt32BigEndian(ihdr.AsSpan(0, 4), 100);
        BinaryPrimitives.WriteUInt32BigEndian(ihdr.AsSpan(4, 4), 80);
        ihdr[8] = 8; ihdr[9] = 2;
        WritePngChunk(ms, "IHDR", ihdr);
        WritePngChunk(ms, "sRGB", [0]);
        WritePngChunk(ms, "pHYs", [0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1]);
        WritePngChunk(ms, "tIME", [0x07, 0xEA, 5, 1, 10, 20, 30]);
        WritePngChunk(ms, "tEXt", Encoding.Latin1.GetBytes("Author\0Jane Doe"));
        WritePngChunk(ms, "tEXt", Encoding.Latin1.GetBytes("Software\0GIMP 2.10"));
        WritePngChunk(ms, "eXIf", BuildTestTiffExifBytes());
        WritePngChunk(ms, "IDAT", [0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);
        WritePngChunk(ms, "IEND", []);
        return ms.ToArray();
    }

    private static byte[] BuildTestWavWithInfo()
    {
        using var body = new MemoryStream();
        body.Write("WAVE"u8);

        var fmt = new byte[16];
        BinaryPrimitives.WriteUInt16LittleEndian(fmt.AsSpan(0, 2), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(fmt.AsSpan(2, 2), 2);
        BinaryPrimitives.WriteUInt32LittleEndian(fmt.AsSpan(4, 4), 44100);
        BinaryPrimitives.WriteUInt16LittleEndian(fmt.AsSpan(14, 2), 16);
        WriteRiffChunk(body, "fmt ", fmt);

        using var info = new MemoryStream();
        info.Write("INFO"u8);
        WriteRiffChunk(info, "IART", Encoding.UTF8.GetBytes("Secret Artist\0"));
        WriteRiffChunk(info, "ISFT", Encoding.UTF8.GetBytes("Audacity\0"));
        WriteRiffChunk(body, "LIST", info.ToArray());
        WriteRiffChunk(body, "data", [0, 0, 0, 0]);

        var result = new byte[8 + body.Length];
        "RIFF"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), (uint)body.Length);
        body.ToArray().CopyTo(result, 8);
        return result;
    }

    private static byte[] BuildTestGifWithComment()
    {
        using var ms = new MemoryStream();
        ms.Write("GIF89a"u8);
        ms.Write([10, 0, 10, 0, 0x00, 0, 0]); // 10x10, no GCT
        // Comment Extension (0x21 0xFE)
        var comment = "Private author comment"u8;
        ms.Write([0x21, 0xFE, (byte)comment.Length]);
        ms.Write(comment);
        ms.WriteByte(0); // sub-block terminator
        // Image Descriptor + minimal LZW data + Trailer
        ms.Write([0x2C, 0, 0, 0, 0, 10, 0, 10, 0, 0x00, 2, 2, 0x44, 0x01, 0, 0x3B]);
        return ms.ToArray();
    }

    private static byte[] BuildTestWebpWithExif()
    {
        using var body = new MemoryStream();
        body.Write("WEBP"u8);
        var vp8x = new byte[10];
        vp8x[0] = 0x08 | 0x04; // EXIF + XMP flags
        vp8x[4] = 99; vp8x[7] = 79; // 100x80
        WriteRiffChunk(body, "VP8X", vp8x);
        WriteRiffChunk(body, "VP8 ", [0, 0, 0, 0]);
        WriteRiffChunk(body, "EXIF", BuildTestTiffExifBytes());
        WriteRiffChunk(body, "XMP ", Encoding.UTF8.GetBytes("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:creator>Alice</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>"));

        var result = new byte[8 + body.Length];
        "RIFF"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4, 4), (uint)body.Length);
        body.ToArray().CopyTo(result, 8);
        return result;
    }

    private static void WriteSegment(Stream ms, byte marker, byte[] payload)
    {
        ms.WriteByte(0xFF);
        ms.WriteByte(marker);
        Span<byte> len = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)(payload.Length + 2));
        ms.Write(len);
        ms.Write(payload);
    }

    private static void WritePngChunk(Stream ms, string type, byte[] data)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)data.Length);
        ms.Write(buf);
        var typeBytes = Encoding.ASCII.GetBytes(type);
        ms.Write(typeBytes);
        ms.Write(data);

        uint crc = 0xFFFFFFFF;
        foreach (byte b in typeBytes) { crc ^= b; for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1; }
        foreach (byte b in data) { crc ^= b; for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1; }
        BinaryPrimitives.WriteUInt32BigEndian(buf, crc ^ 0xFFFFFFFF);
        ms.Write(buf);
    }

    private static void WriteRiffChunk(Stream ms, string fourcc, byte[] payload)
    {
        ms.Write(Encoding.ASCII.GetBytes(fourcc));
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)payload.Length);
        ms.Write(len);
        ms.Write(payload);
        if ((payload.Length & 1) == 1) ms.WriteByte(0);
    }

    private static byte[] Rational(uint num, uint den)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(0, 4), num);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4, 4), den);
        return b;
    }

    private static uint MeasureIfd(List<(ushort Tag, ushort Type, uint Count, byte[] Data)> entries)
    {
        uint extra = 0;
        foreach (var e in entries)
            if (e.Data.Length > 4) extra += (uint)e.Data.Length + ((uint)e.Data.Length & 1u);
        return (uint)(2 + entries.Count * 12 + 4) + extra;
    }

    private static void WriteIfd(Stream ms, List<(ushort Tag, ushort Type, uint Count, byte[] Data)> entries, uint start, uint nextOffset)
    {
        var sorted = entries.OrderBy(e => e.Tag).ToList();
        uint cursor = start + (uint)(2 + sorted.Count * 12 + 4);
        using var extra = new MemoryStream();
        ms.Write(BitConverter.GetBytes((ushort)sorted.Count));
        foreach (var e in sorted)
        {
            ms.Write(BitConverter.GetBytes(e.Tag));
            ms.Write(BitConverter.GetBytes(e.Type));
            ms.Write(BitConverter.GetBytes(e.Count));
            if (e.Data.Length <= 4)
            {
                var buf = new byte[4];
                e.Data.CopyTo(buf, 0);
                ms.Write(buf);
            }
            else
            {
                ms.Write(BitConverter.GetBytes(cursor));
                extra.Write(e.Data);
                if ((e.Data.Length & 1) == 1) extra.WriteByte(0);
                cursor += (uint)e.Data.Length + ((uint)e.Data.Length & 1u);
            }
        }
        ms.Write(BitConverter.GetBytes(nextOffset));
        extra.Position = 0;
        extra.CopyTo(ms);
    }
    #endregion
}
