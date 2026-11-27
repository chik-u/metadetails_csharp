using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows.Forms;
using MetaDetective.Api.MetaCore;

namespace MetaGuard.Desktop;

internal static class Program
{
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    private const int AttachParentProcess = -1;

    [STAThread]
    private static int Main(string[] args)
    {
        var engine = new MetaCoreEngine();
        var extractor = new MetadataExtractorService();
        var sanitizer = new FileSanitizerService(engine, extractor);
        var mediator = new OsMediationService(engine, extractor, sanitizer);

        if (args.Contains("--install-shell", StringComparer.OrdinalIgnoreCase))
        {
            AttachConsole(AttachParentProcess);
            ShellIntegration.Install();
            Console.WriteLine($"Installed MetaGuard Windows SendTo shortcut ({ShellIntegration.SendToShortcutPath}) and HKCU Explorer context menu.");
            return 0;
        }

        if (args.Contains("--uninstall-shell", StringComparer.OrdinalIgnoreCase))
        {
            AttachConsole(AttachParentProcess);
            ShellIntegration.Uninstall();
            Console.WriteLine("Uninstalled MetaGuard Windows shell integration.");
            return 0;
        }

        if (args.Contains("--mediate", StringComparer.OrdinalIgnoreCase))
        {
            AttachConsole(AttachParentProcess);
            return RunCliMediateAsync(mediator, args).GetAwaiter().GetResult();
        }

        ApplicationConfiguration.Initialize();
        var fileArgs = args.Where(a => !a.StartsWith("--") && File.Exists(a)).ToArray();
        Application.Run(new MediationForm(mediator, fileArgs));
        return 0;
    }

    private static async Task<int> RunCliMediateAsync(OsMediationService mediator, string[] args)
    {
        bool jsonOutput = args.Contains("--json", StringComparer.OrdinalIgnoreCase);
        bool noTier3 = args.Contains("--no-tier3", StringComparer.OrdinalIgnoreCase);

        string? outDir = null;
        var files = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--out", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                outDir = args[++i];
            }
            else if (!args[i].StartsWith("--") && File.Exists(args[i]))
            {
                files.Add(args[i]);
            }
        }

        if (files.Count == 0)
        {
            Console.Error.WriteLine("Usage: MetaGuard.Desktop --mediate <file1> [file2...] [--out <dir>] [--no-tier3] [--json]");
            return 1;
        }

        var inputs = new List<OsMediationInput>(files.Count);
        foreach (var path in files)
        {
            inputs.Add(new OsMediationInput
            {
                FileName = Path.GetFileName(path),
                ContentType = FileSanitizerService.InferContentType(Path.GetExtension(path).ToLowerInvariant()),
                Payload = await File.ReadAllBytesAsync(path),
                SourceChannel = "windows-cli-mediator"
            });
        }

        var opts = OsMediationService.CreateDefaultMediationOptions();
        opts.EnableTier3Normalization = !noTier3;

        var (batch, items) = await mediator.MediateBatchAsync(inputs, opts, "windows-cli-mediator");

        if (!string.IsNullOrWhiteSpace(outDir))
        {
            Directory.CreateDirectory(outDir);
            foreach (var (res, bytes) in items)
                await File.WriteAllBytesAsync(Path.Combine(outDir, res.SanitizedFileName), bytes);
        }

        if (jsonOutput)
        {
            Console.WriteLine(JsonSerializer.Serialize(batch, new JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            Console.WriteLine($"MetaGuard Zero-Transit OS Mediation ({batch.MediationMode}) | Mean PRI: {batch.MeanBeforePri:F1} -> {batch.MeanAfterPri:F1} (PER: {batch.MeanPerPercent:F1}%) | Usability: {batch.MeanUsabilityScore:F1}% | {batch.TotalLatencyMs:F2} ms");
            foreach (var a in batch.Assets)
            {
                Console.WriteLine($"  - {a.FileName} -> {a.SanitizedFileName}: PRI {a.BeforePri:F1}->{a.AfterPri:F1}, Tampered={a.TamperAudit.IsTampered}, RemainingSensitive={a.RemainingSensitiveFields.Count}, Latency={a.ProcessingLatencyMs:F2}ms");
            }
        }

        return batch.Assets.Count > 0 ? 0 : 2;
    }
}
