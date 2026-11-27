using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json.Nodes;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Ephemeral store for sanitized output files so the UI can inspect the MetaCore report
/// and download the sanitized artifact without re-uploading.
/// </summary>
public sealed class SanitizedFileStore
{
    public sealed record StoredSanitizedFile(
        string FileName,
        string ContentType,
        byte[] Content,
        DateTime ExpiresAtUtc);

    private readonly ConcurrentDictionary<string, StoredSanitizedFile> _entries = new();

    public string Save(string fileName, string contentType, byte[] content, TimeSpan? ttl = null)
    {
        PruneExpired();
        var id = Guid.NewGuid().ToString("N");
        _entries[id] = new StoredSanitizedFile(
            fileName,
            contentType,
            content,
            DateTime.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(15)));
        return id;
    }

    public bool TryGet(string id, out StoredSanitizedFile? file)
    {
        PruneExpired();
        if (_entries.TryGetValue(id, out var entry) && entry.ExpiresAtUtc > DateTime.UtcNow)
        {
            file = entry;
            return true;
        }
        file = null;
        return false;
    }

    private void PruneExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in _entries)
        {
            if (kvp.Value.ExpiresAtUtc <= now)
                _entries.TryRemove(kvp.Key, out _);
        }
    }
}

/// <summary>
/// Orchestrates selective file sanitization using the MetaCore priority engine.
/// Keeps Required and Low-priority metadata while stripping Sensitive (High/Critical) metadata.
/// </summary>
public sealed class FileSanitizerService
{
    private static readonly Lazy<bool> FfmpegAvailable = new(() => MetadataExtractorService.IsExecutableAvailable("ffmpeg", "-version"));
    private static readonly HashSet<string> MediaExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".m4a", ".flac"
    };

    private readonly MetaCoreEngine _engine;
    private readonly MetadataExtractorService _extractor;

    public FileSanitizerService(MetaCoreEngine engine, MetadataExtractorService extractor)
    {
        _engine = engine;
        _extractor = extractor;
    }

    public async Task<(SanitizationResult Result, byte[] SanitizedBytes)> SanitizeFileAsync(
        string inputPath,
        string originalFileName,
        string? contentType,
        MetaSanitizeOptions? options = null)
    {
        options ??= new MetaSanitizeOptions();
        var safeFileName = Path.GetFileName(originalFileName);
        var ext = Path.GetExtension(safeFileName).ToLowerInvariant();
        var outputPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}_sanitized{ext}");

        try
        {
            // 1. Extract and classify original metadata
            var (beforeMeta, _) = await _extractor.ExtractAsync(inputPath, safeFileName);
            var beforeReport = _engine.AnalyzeMetadata(beforeMeta, options);
            var originalSize = new FileInfo(inputPath).Length;

            // 2. Sanitize file selectively (keep Required + Low, strip High + Critical)
            string engineUsed;
            if (ext is ".svg" or ".wav" or ".pdf" or ".docx" or ".pptx" or ".xlsx" && (!FfmpegAvailable.Value || ext is ".svg" or ".pdf" or ".docx" or ".pptx" or ".xlsx"))
            {
                NativeBinaryMetadataHandler.SanitizeFile(inputPath, outputPath, beforeReport, safeFileName);
                engineUsed = $"MetaCore Native Binary Sanitizer ({ext.TrimStart('.').ToUpperInvariant()})";
            }
            else if (MediaExtensions.Contains(ext) && FfmpegAvailable.Value)
            {
                await SanitizeWithFfmpegAsync(inputPath, outputPath, beforeReport);
                engineUsed = "FFmpeg + MetaCore";
            }
            else if (_extractor.HasExifTool && ext is not ".mp4" and not ".mov" and not ".m4a")
            {
                await SanitizeWithExifToolAsync(inputPath, outputPath, beforeReport);
                engineUsed = "ExifTool + MetaCore";
            }
            else if (NativeBinaryMetadataHandler.IsSupported(safeFileName))
            {
                NativeBinaryMetadataHandler.SanitizeFile(inputPath, outputPath, beforeReport, safeFileName);
                engineUsed = $"MetaCore Native Binary Sanitizer ({ext.TrimStart('.').ToUpperInvariant()})";
            }
            else
            {
                throw new NotSupportedException(
                    $"Cannot sanitize '{safeFileName}': install ExifTool or FFmpeg for '{ext}' files.");
            }

            var sanitizedBytes = await File.ReadAllBytesAsync(outputPath);

            // 3. Re-extract and verify sanitized artifact
            var (afterMeta, _) = await _extractor.ExtractAsync(outputPath, $"sanitized_{safeFileName}");
            var afterReport = _engine.AnalyzeMetadata(afterMeta, options);

            var afterKeys = new HashSet<string>(
                afterReport.Details.Select(d => d.NormalizedKey),
                StringComparer.OrdinalIgnoreCase);

            var removedFields = beforeReport.Details
                .Where(d => d.Action == MetaAction.Remove && !d.IsRuntimeSynthetic && !afterKeys.Contains(d.NormalizedKey))
                .ToList();

            var remainingSensitive = afterReport.Details
                .Where(d => d.IsSensitive && !d.IsRuntimeSynthetic)
                .ToList();

            var keptFields = afterReport.Details
                .Where(d => !d.IsRuntimeSynthetic)
                .ToList();

            var tamperAudit = TamperDetectionService.Audit(beforeMeta);
            var per = PrivacyRiskEvaluator.CalculatePer(beforeReport.PrivacyRiskIndex, afterReport.PrivacyRiskIndex);
            var usability = PrivacyRiskEvaluator.EvaluateUsability(safeFileName, beforeReport, afterReport);
            var generalizedFields = beforeReport.Details
                .Where(d => d.Action == MetaAction.Normalize && !d.IsRuntimeSynthetic)
                .ToList();

            var result = new SanitizationResult
            {
                FileName = safeFileName,
                SanitizedFileName = $"sanitized_{safeFileName}",
                ContentType = string.IsNullOrWhiteSpace(contentType) ? InferContentType(ext) : contentType,
                OriginalSize = originalSize,
                SanitizedSize = sanitizedBytes.LongLength,
                BytesRemoved = Math.Max(0, originalSize - sanitizedBytes.LongLength),
                EngineUsed = engineUsed,
                PrivacyExposureReductionPercent = per,
                BeforeReport = beforeReport,
                AfterReport = afterReport,
                TamperAudit = tamperAudit,
                Usability = usability,
                RemovedFields = removedFields,
                GeneralizedFields = generalizedFields,
                KeptFields = keptFields,
                RemainingSensitiveFields = remainingSensitive
            };

            return (result, sanitizedBytes);
        }
        finally
        {
            if (File.Exists(outputPath))
                File.Delete(outputPath);
        }
    }

    private static async Task SanitizeWithExifToolAsync(string inputPath, string outputPath, MetaCoreReport report)
    {
        var args = new List<string> { "-all=" };
        var writableTags = report.WritablePreserveTags
            .Where(t => !t.StartsWith("Profile", StringComparison.OrdinalIgnoreCase) &&
                        !t.Equals("ICCProfileName", StringComparison.OrdinalIgnoreCase))
            .ToList();

        bool keepIcc = report.WritablePreserveTags.Any(t =>
            t.Equals("ICCProfileName", StringComparison.OrdinalIgnoreCase) ||
            t.StartsWith("Profile", StringComparison.OrdinalIgnoreCase));

        if (writableTags.Count > 0 || keepIcc)
        {
            args.Add("-tagsFromFile");
            args.Add("@");
            foreach (var tag in writableTags)
                args.Add($"-{tag}");
            if (keepIcc)
                args.Add("-icc_profile");
        }

        args.Add("-o");
        args.Add(outputPath);
        args.Add(inputPath);

        var psi = new ProcessStartInfo
        {
            FileName = "exiftool",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Could not start exiftool.");
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var stderr = await stderrTask;

        if (!File.Exists(outputPath))
            throw new InvalidOperationException($"ExifTool failed to produce sanitized file (exit {process.ExitCode}): {stderr.Trim()}");
    }

    private static async Task SanitizeWithFfmpegAsync(string inputPath, string outputPath, MetaCoreReport report)
    {
        var args = new List<string>
        {
            "-y",
            "-i", inputPath,
            "-map_metadata", "-1",
            "-map_chapters", "-1",
            "-c", "copy"
        };

        // Preserve any explicitly kept string container tags (e.g. language/rotate) if present
        foreach (var detail in report.Details.Where(d => d.Action == MetaAction.Keep && d.IsEmbeddedWritable && !d.IsRuntimeSynthetic))
        {
            var val = detail.Value?.ToString();
            if (!string.IsNullOrWhiteSpace(val) && detail.NormalizedKey.Equals("Rotate", StringComparison.OrdinalIgnoreCase))
            {
                args.Add("-metadata:s:v:0");
                args.Add($"rotate={val}");
            }
        }

        args.Add(outputPath);
        await MetadataExtractorService.RunProcessAsync("ffmpeg", args);
        if (!File.Exists(outputPath))
            throw new InvalidOperationException("FFmpeg failed to produce sanitized output.");
    }

    public static string InferContentType(string ext) => ext switch
    {
        ".jpg" or ".jpeg" => "image/jpeg",
        ".png" => "image/png",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        ".svg" => "image/svg+xml",
        ".wav" => "audio/wav",
        ".mp3" => "audio/mpeg",
        ".m4a" => "audio/mp4",
        ".mp4" => "video/mp4",
        ".mov" => "video/quicktime",
        ".pdf" => "application/pdf",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream"
    };
}
