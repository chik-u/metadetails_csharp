using System.Buffers.Binary;
using System.IO.Compression;
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

    [Fact]
    public void PrivacyRiskEvaluator_ComputesCompoundPriAndClusterSynergies()
    {
        var metadata = new JsonObject
        {
            ["Orientation"] = 1,
            ["ISO"] = 200,
            ["GPSLatitude"] = "28.6139",
            ["GPSLongitude"] = "77.2090",
            ["DateTimeOriginal"] = "2026:05:10 14:20:00",
            ["Make"] = "Canon",
            ["SerialNumber"] = "SN-424242",
            ["Artist"] = "Manvendra Singh"
        };

        var report = _engine.AnalyzeMetadata(metadata);

        Assert.Contains(report.RiskClusters, c => c.ClusterId == "K_geo-time");
        Assert.Contains(report.RiskClusters, c => c.ClusterId == "K_device");
        Assert.Contains(report.RiskClusters, c => c.ClusterId == "K_identity");
        Assert.True(report.PrivacyRiskIndex >= 50.0);
        Assert.Equal("Critical Risk", report.PriRiskBand);
    }

    [Fact]
    public void TamperDetectionService_DetectsAllFourHeuristicAnomalies_AndPassesConsistentFile()
    {
        var tamperedMeta = new JsonObject
        {
            ["Make"] = "Canon",
            ["Model"] = "EOS R6",
            ["ExposureTime"] = "1/125",
            ["Software"] = "Adobe Photoshop CC 2025",
            ["DateTimeOriginal"] = "2026:05:10 15:00:00",
            ["ModifyDate"] = "2026:05:09 10:00:00", // Earlier than Create -> tau_chron
            ["GPSLatitude"] = "40.7128" // Missing longitude -> tau_clust
        };

        var audit = TamperDetectionService.Audit(tamperedMeta);
        Assert.True(audit.IsTampered);
        Assert.Contains(audit.Flags, f => f.RuleId == "tau_chron");
        Assert.Contains(audit.Flags, f => f.RuleId == "tau_soft");
        Assert.Contains(audit.Flags, f => f.RuleId == "tau_clust");

        // Solar time divergence test (tau_geo): Lon -75 => solar offset -5h; GPS UTC 17:00 => solar ~12:00, vs local 21:00 (diff 9h > 2.5h)
        var spoofedSolarMeta = new JsonObject
        {
            ["GPSLatitude"] = "40.7128",
            ["GPSLongitude"] = "-75.0",
            ["GPSTimeStamp"] = "17:00:00",
            ["DateTimeOriginal"] = "2026:05:10 21:00:00"
        };
        var solarAudit = TamperDetectionService.Audit(spoofedSolarMeta);
        Assert.Contains(solarAudit.Flags, f => f.RuleId == "tau_geo");

        // Consistent file should produce zero tamper flags
        var cleanAudit = TamperDetectionService.Audit(new JsonObject
        {
            ["Make"] = "Google",
            ["Model"] = "Pixel 9",
            ["DateTimeOriginal"] = "2026:05:10 12:15:00",
            ["ModifyDate"] = "2026:05:10 12:16:00",
            ["GPSLatitude"] = "40.7128",
            ["GPSLongitude"] = "-75.0",
            ["GPSTimeStamp"] = "17:00:00"
        });
        Assert.False(cleanAudit.IsTampered);
    }

    [Fact]
    public async Task OsMediationService_MediatesPdfOpenXmlAndMp4InVolatileMemory_PreservingUtility()
    {
        var mediator = new OsMediationService(_engine, new MetadataExtractorService(), new FileSanitizerService(_engine, new MetadataExtractorService()));

        var inputs = new List<OsMediationInput>
        {
            new() { FileName = "report.pdf", ContentType = "application/pdf", Payload = BuildTestPdfWithStructTree(), SourceChannel = "android-action-send-multiple" },
            new() { FileName = "slides.docx", ContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", Payload = BuildTestDocxWithMetadata(), SourceChannel = "android-action-send-multiple" },
            new() { FileName = "clip.mp4", ContentType = "video/mp4", Payload = BuildTestMp4WithMetadata(), SourceChannel = "android-action-send-multiple" },
            new() { FileName = "shot.jpg", ContentType = "image/jpeg", Payload = BuildTestJpegWithFullMetadata(), SourceChannel = "android-action-send-multiple" }
        };

        var (batch, items) = await mediator.MediateBatchAsync(inputs, OsMediationService.CreateDefaultMediationOptions(), "android-action-send-multiple");

        Assert.Equal("ACTION_SEND_MULTIPLE", batch.MediationMode);
        Assert.True(batch.ZeroTransitVerified);
        Assert.Empty(batch.Errors);
        Assert.Equal(4, batch.Assets.Count);
        Assert.All(batch.Assets, a =>
        {
            Assert.True(a.VolatileMemoryOnly);
            Assert.True(a.ZeroTransitVerified);
            Assert.Empty(a.RemainingSensitiveFields);
            Assert.True(a.AfterPri < a.BeforePri);
            Assert.Equal(100.0, a.Usability.CompositeUsabilityScore);
        });

        // Verify PDF/UA accessibility tree survived sanitization
        var (pdfRes, pdfClean) = items.Single(x => x.Result.FileName == "report.pdf");
        Assert.True(pdfRes.Usability.HadPdfAccessibilityTree);
        Assert.True(pdfRes.Usability.PdfAccessibilityPreserved);
        var pdfMetaAfter = NativeBinaryMetadataHandler.ExtractMetadata(pdfClean.AsMemory(), "clean.pdf");
        Assert.False(pdfMetaAfter.ContainsKey("Author"));
        Assert.True(pdfMetaAfter["HasStructTreeRoot"]?.GetValue<bool>());

        // Verify DOCX OpenXML integrity and absence of Author / Custom properties / comments
        var (docxRes, docxClean) = items.Single(x => x.Result.FileName == "slides.docx");
        Assert.True(docxRes.Usability.OpenXmlIntegrityPreserved);
        var docxMetaAfter = NativeBinaryMetadataHandler.ExtractMetadata(docxClean.AsMemory(), "clean.docx");
        Assert.False(docxMetaAfter.ContainsKey("Author"));
        Assert.False(docxMetaAfter.ContainsKey("Company"));
        Assert.False(docxMetaAfter.ContainsKey("Comments"));
        Assert.True(docxMetaAfter["OpenXMLIntegrity"]?.GetValue<bool>());

        // Verify MP4 stripped GPSCoordinates & Artist while retaining tkhd rotation (90 deg) & updating stco chunk offset cleanly
        var (_, mp4Clean) = items.Single(x => x.Result.FileName == "clip.mp4");
        var mp4MetaAfter = NativeBinaryMetadataHandler.ExtractMetadata(mp4Clean.AsMemory(), "clean.mp4");
        Assert.False(mp4MetaAfter.ContainsKey("GPSCoordinates"));
        Assert.False(mp4MetaAfter.ContainsKey("Artist"));
        Assert.Equal(90, mp4MetaAfter["Rotate"]?.GetValue<int>());
        Assert.Contains(mp4Clean, b => b == 0xAA); // Verify mdat payload preserved
        int stcoIdx = mp4Clean.AsSpan().IndexOf("stco"u8);
        int mdatIdx = mp4Clean.AsSpan().IndexOf("mdat"u8);
        Assert.True(stcoIdx > 0 && mdatIdx > stcoIdx);
        uint updatedChunkOffset = BinaryPrimitives.ReadUInt32BigEndian(mp4Clean.AsSpan(stcoIdx + 12, 4));
        Assert.Equal((uint)(mdatIdx + 4), updatedChunkOffset);
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

    private static byte[] BuildTestPdfWithStructTree()
    {
        using var ms = new MemoryStream();
        void W(string s) => ms.Write(Encoding.Latin1.GetBytes(s));

        W("%PDF-1.7\n");
        var offsets = new Dictionary<int, long>();

        offsets[1] = ms.Position;
        W("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /StructTreeRoot 4 0 R /MarkInfo << /Marked true >> >>\nendobj\n");

        offsets[2] = ms.Position;
        W("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        offsets[3] = ms.Position;
        W("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        offsets[4] = ms.Position;
        W("4 0 obj\n<< /Type /StructTreeRoot >>\nendobj\n");

        offsets[5] = ms.Position;
        W("5 0 obj\n<< /Title (Confidential Draft) /Author (Manvendra Singh) /Producer (Secret PDF Tool) /CreationDate (D:20260514113000Z) >>\nendobj\n");

        long xref = ms.Position;
        W("xref\n0 6\n0000000000 65535 f \n");
        for (int i = 1; i <= 5; i++)
            W($"{offsets[i]:D10} 00000 n \n");

        W($"trailer\n<< /Size 6 /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return ms.ToArray();
    }

    private static byte[] BuildTestDocxWithMetadata()
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, string content)
            {
                var entry = zip.CreateEntry(name);
                using var s = new StreamWriter(entry.Open(), new UTF8Encoding(false));
                s.Write(content);
            }

            Add("[Content_Types].xml", "<?xml version=\"1.0\" encoding=\"utf-8\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>");
            Add("_rels/.rels", "<?xml version=\"1.0\" encoding=\"utf-8\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>");
            Add("word/document.xml", "<?xml version=\"1.0\" encoding=\"utf-8\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>");
            Add("word/comments.xml", "<?xml version=\"1.0\" encoding=\"utf-8\"?><w:comments xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:comment w:id=\"1\"><w:p><w:r><w:t>Internal note</w:t></w:r></w:p></w:comment></w:comments>");
            Add("docProps/core.xml", "<?xml version=\"1.0\" encoding=\"utf-8\"?><cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\"><dc:creator>Manish Verma</dc:creator><cp:lastModifiedBy>AdminPC</cp:lastModifiedBy><dcterms:created>2026-05-14T10:30:00Z</dcterms:created></cp:coreProperties>");
            Add("docProps/app.xml", "<?xml version=\"1.0\" encoding=\"utf-8\"?><Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"><Application>Microsoft Word 365</Application><Company>ABES Corp</Company><Pages>20</Pages></Properties>");
        }
        return ms.ToArray();
    }

    private static byte[] BuildTestMp4WithMetadata()
    {
        static byte[] Box(string fourcc, params byte[][] parts)
        {
            int len = 8 + parts.Sum(p => p.Length);
            var buf = new byte[len];
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(0, 4), (uint)len);
            Encoding.Latin1.GetBytes(fourcc, buf.AsSpan(4, 4));
            int p = 8;
            foreach (var part in parts)
            {
                part.CopyTo(buf, p);
                p += part.Length;
            }
            return buf;
        }

        // ftyp (16 bytes)
        var ftyp = Box("ftyp", Encoding.Latin1.GetBytes("isom\0\0\x02\0"));

        // mvhd (version 0, create/mod 3800000000s, timescale 1000, dur 5000)
        var mvhdPayload = new byte[96];
        BinaryPrimitives.WriteUInt32BigEndian(mvhdPayload.AsSpan(4, 4), 3800000000u);
        BinaryPrimitives.WriteUInt32BigEndian(mvhdPayload.AsSpan(8, 4), 3800000000u);
        BinaryPrimitives.WriteUInt32BigEndian(mvhdPayload.AsSpan(12, 4), 1000u);
        BinaryPrimitives.WriteUInt32BigEndian(mvhdPayload.AsSpan(16, 4), 5000u);
        var mvhd = Box("mvhd", mvhdPayload);

        // tkhd (90 deg rotation matrix: a=0, b=1 (65536), c=-1 (-65536), d=0, width=1920, height=1080)
        var tkhdPayload = new byte[84];
        BinaryPrimitives.WriteInt32BigEndian(tkhdPayload.AsSpan(40, 4), 0);
        BinaryPrimitives.WriteInt32BigEndian(tkhdPayload.AsSpan(44, 4), 65536);
        BinaryPrimitives.WriteInt32BigEndian(tkhdPayload.AsSpan(52, 4), -65536);
        BinaryPrimitives.WriteInt32BigEndian(tkhdPayload.AsSpan(56, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(tkhdPayload.AsSpan(76, 4), 1920u << 16);
        BinaryPrimitives.WriteUInt32BigEndian(tkhdPayload.AsSpan(80, 4), 1080u << 16);
        var tkhd = Box("tkhd", tkhdPayload);

        // stco pointing initially to mdat data offset (placeholder patched once moov size is known)
        var stcoPayload = new byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(stcoPayload.AsSpan(4, 4), 1u);
        var stbl = Box("stbl", Box("stco", stcoPayload));
        var trakWithoutOffset = Box("trak", tkhd, Box("mdia", Box("minf", stbl)));

        // udta with ©xyz GPS and meta/ilst ©ART
        var xyzText = "+28.6139+077.2090/";
        var xyzPayload = new byte[4 + xyzText.Length];
        BinaryPrimitives.WriteUInt16BigEndian(xyzPayload.AsSpan(0, 2), (ushort)xyzText.Length);
        Encoding.UTF8.GetBytes(xyzText).CopyTo(xyzPayload, 4);
        var xyzBox = Box("\u00a9xyz", xyzPayload);

        var dataPayload = new byte[16 + "SecretCreator".Length];
        Encoding.Latin1.GetBytes("data", dataPayload.AsSpan(4, 4));
        Encoding.UTF8.GetBytes("SecretCreator").CopyTo(dataPayload, 16);
        var artBox = Box("\u00a9ART", dataPayload);
        var ilstBox = Box("ilst", artBox);
        var metaPayload = new byte[4 + ilstBox.Length];
        ilstBox.CopyTo(metaPayload, 4);
        var udta = Box("udta", xyzBox, Box("meta", metaPayload));

        var moov = Box("moov", mvhd, trakWithoutOffset, udta);
        var mdat = Box("mdat", [0xAA, 0xBB, 0xCC, 0xDD]);

        var combined = new byte[ftyp.Length + moov.Length + mdat.Length];
        ftyp.CopyTo(combined, 0);
        moov.CopyTo(combined, ftyp.Length);
        mdat.CopyTo(combined, ftyp.Length + moov.Length);
        int initStcoIdx = combined.AsSpan().IndexOf("stco"u8);
        BinaryPrimitives.WriteUInt32BigEndian(combined.AsSpan(initStcoIdx + 12, 4), (uint)(ftyp.Length + moov.Length + 8));
        return combined;
    }
    #endregion
}
