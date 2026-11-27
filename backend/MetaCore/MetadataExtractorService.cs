using System.Diagnostics;
using System.Text.Json.Nodes;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Extracts metadata from uploaded files using ExifTool (plus Tesseract OCR and FFprobe when available),
/// falling back seamlessly to the pure C# native parser for common formats when ExifTool is not installed.
/// </summary>
public sealed class MetadataExtractorService
{
    private static readonly Lazy<bool> ExifToolAvailable = new(() => IsExecutableAvailable("exiftool", "-ver"));
    private static readonly Lazy<bool> TesseractAvailable = new(() => IsExecutableAvailable("tesseract", "--version"));
    private static readonly Lazy<bool> FfprobeAvailable = new(() => IsExecutableAvailable("ffprobe", "-version"));

    public bool HasExifTool => ExifToolAvailable.Value;

    public async Task<(JsonObject Metadata, string Engine)> ExtractAsync(string filePath, string originalFileName)
    {
        JsonObject? metadata = null;
        string engine;

        var extLower = Path.GetExtension(originalFileName).ToLowerInvariant();
        if (NativeBinaryMetadataHandler.IsSupported(originalFileName) &&
            extLower is ".pdf" or ".docx" or ".pptx" or ".xlsx" or ".svg" or ".wav")
        {
            metadata = NativeBinaryMetadataHandler.ExtractMetadata(filePath, originalFileName);
            engine = "MetaCore Native Binary Parser";
        }
        else if (HasExifTool)
        {
            var output = await RunProcessAsync("exiftool", ["-j", filePath]);
            var jsonArray = JsonNode.Parse(string.IsNullOrWhiteSpace(output) ? "[]" : output) as JsonArray;
            if (jsonArray is { Count: > 0 } && jsonArray[0] is JsonObject obj)
            {
                metadata = obj;
                // Preserve user's original uploaded filename rather than the temp UUID filename.
                metadata["FileName"] = originalFileName;
            }
            engine = "ExifTool";
        }
        else if (NativeBinaryMetadataHandler.IsSupported(originalFileName))
        {
            metadata = NativeBinaryMetadataHandler.ExtractMetadata(filePath, originalFileName);
            engine = "MetaCore Native Binary Parser";
        }
        else
        {
            throw new InvalidOperationException(
                $"ExifTool is not installed on the server and native extraction does not support '{Path.GetExtension(originalFileName)}'.");
        }

        metadata ??= new JsonObject { ["FileName"] = originalFileName };

        var ext = Path.GetExtension(originalFileName).ToLowerInvariant();
        if (ext is ".png" or ".jpg" or ".jpeg" && TesseractAvailable.Value)
        {
            try
            {
                var ocr = await RunProcessAsync("tesseract", [filePath, "stdout"]);
                if (!string.IsNullOrWhiteSpace(ocr))
                    metadata["OCRText"] = ocr.Trim();
            }
            catch { }
        }
        else if (ext is ".mp4" or ".avi" or ".mov" or ".mp3" or ".wav" && FfprobeAvailable.Value)
        {
            try
            {
                var ffprobe = await RunProcessAsync("ffprobe", ["-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", filePath]);
                if (!string.IsNullOrWhiteSpace(ffprobe))
                    metadata["FFprobe"] = JsonNode.Parse(ffprobe.Trim());
            }
            catch { }
        }

        return (metadata, engine);
    }

    public static bool IsExecutableAvailable(string fileName, string versionArg)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(versionArg);
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            proc.WaitForExit(3000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<string> RunProcessAsync(string fileName, IReadOnlyList<string> args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        var stdOutTask = process.StandardOutput.ReadToEndAsync();
        var stdErrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        var stdout = await stdOutTask;
        var stderr = await stdErrTask;

        if (process.ExitCode != 0 && string.IsNullOrWhiteSpace(stdout))
            throw new InvalidOperationException($"{fileName} exited with code {process.ExitCode}: {stderr.Trim()}");

        return stdout;
    }
}
