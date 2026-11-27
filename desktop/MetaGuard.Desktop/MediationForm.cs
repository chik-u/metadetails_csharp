using System.Collections.Specialized;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using MetaDetective.Api.MetaCore;

namespace MetaGuard.Desktop;

public sealed class MediationForm : Form
{
    private readonly OsMediationService _mediator;
    private readonly List<(MediatedAssetResult Result, byte[] Bytes)> _mediatedItems = new();
    private readonly List<string> _stagedPaths = new();

    private readonly Label _statusLabel;
    private readonly Label _metricsLabel;
    private readonly CheckBox _tier3Box;
    private readonly Button _copyClipboardBtn;
    private readonly Button _saveAllBtn;
    private readonly Button _shellToggleBtn;
    private readonly TextBox _detailsBox;

    public MediationForm(OsMediationService mediator, string[] initialFiles)
    {
        _mediator = mediator;

        Text = "MetaGuard OS Mediation Layer — Desktop Share Guard";
        MinimumSize = new Size(820, 580);
        Size = new Size(880, 640);
        BackColor = Color.FromArgb(15, 23, 42);
        ForeColor = Color.FromArgb(248, 250, 252);
        AllowDrop = true;
        Font = new Font("Segoe UI", 9.5f);

        var header = new Label
        {
            Text = "MetaGuard Desktop OS Mediator  |  Zero-Transit (T_transit = 0)  |  Volatile RAM Pipeline",
            Dock = DockStyle.Top,
            Height = 36,
            Padding = new Padding(14, 10, 14, 4),
            Font = new Font("Segoe UI", 11f, FontStyle.Bold),
            ForeColor = Color.FromArgb(56, 189, 248)
        };

        var topControls = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 46,
            Padding = new Padding(12, 6, 12, 4),
            FlowDirection = FlowDirection.LeftToRight
        };

        var pickBtn = MakeButton("Select / Drop Files...", Color.FromArgb(30, 41, 59), (_, _) => PickFiles());
        _tier3Box = new CheckBox
        {
            Text = "Tier 3 Generalization (Month/Year + Standard Software)",
            Checked = true,
            AutoSize = true,
            Margin = new Padding(12, 6, 12, 0),
            ForeColor = Color.FromArgb(203, 213, 225)
        };

        _shellToggleBtn = MakeButton(ShellButtonText(), Color.FromArgb(51, 65, 85), (_, _) => ToggleShellIntegration());

        topControls.Controls.Add(pickBtn);
        topControls.Controls.Add(_tier3Box);
        topControls.Controls.Add(_shellToggleBtn);

        _statusLabel = new Label
        {
            Text = "Drag & drop files here or right-click any file -> Send to -> MetaGuard Share Mediator.",
            Dock = DockStyle.Top,
            Height = 28,
            Padding = new Padding(14, 4, 14, 4),
            ForeColor = Color.FromArgb(226, 232, 240)
        };

        _metricsLabel = new Label
        {
            Text = "Mean PRI: --   |   PER: --   |   Usability: --   |   Tamper Alerts: --",
            Dock = DockStyle.Top,
            Height = 30,
            Padding = new Padding(14, 4, 14, 4),
            Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            ForeColor = Color.FromArgb(52, 211, 153)
        };

        var bottomBar = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 52,
            Padding = new Padding(12, 8, 12, 8),
            FlowDirection = FlowDirection.RightToLeft
        };

        _copyClipboardBtn = MakeButton("Safe Dispatch: Copy Clean File(s) to Clipboard", Color.FromArgb(5, 150, 105), (_, _) => CopyCleanToClipboard());
        _copyClipboardBtn.Enabled = false;
        _saveAllBtn = MakeButton("Save Clean Copy As...", Color.FromArgb(2, 132, 199), (_, _) => SaveCleanCopies());
        _saveAllBtn.Enabled = false;

        bottomBar.Controls.Add(_copyClipboardBtn);
        bottomBar.Controls.Add(_saveAllBtn);

        _detailsBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(2, 6, 23),
            ForeColor = Color.FromArgb(226, 232, 240),
            BorderStyle = BorderStyle.FixedSingle,
            Font = new Font("Consolas", 9.5f)
        };

        Controls.Add(_detailsBox);
        Controls.Add(bottomBar);
        Controls.Add(_metricsLabel);
        Controls.Add(_statusLabel);
        Controls.Add(topControls);
        Controls.Add(header);

        DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
                e.Effect = DragDropEffects.Copy;
        };
        DragDrop += async (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] dropped && dropped.Length > 0)
                await MediatePathsAsync(dropped, "windows-drag-drop");
        };

        FormClosed += (_, _) => CleanupStagedFiles();

        if (initialFiles.Length > 0)
            Shown += async (_, _) => await MediatePathsAsync(initialFiles, "windows-shell-sendto");
    }

    private Button MakeButton(string text, Color bg, EventHandler onClick)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            BackColor = bg,
            ForeColor = Color.White,
            Padding = new Padding(8, 3, 8, 3),
            Margin = new Padding(4, 2, 4, 2)
        };
        b.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
        b.Click += onClick;
        return b;
    }

    private static string ShellButtonText() =>
        ShellIntegration.IsInstalled() ? "Uninstall SendTo / Context Menu" : "Install Windows SendTo & Context Menu";

    private void ToggleShellIntegration()
    {
        try
        {
            if (ShellIntegration.IsInstalled())
            {
                ShellIntegration.Uninstall();
                _statusLabel.Text = "Removed Windows Explorer context menu & SendTo integration.";
            }
            else
            {
                ShellIntegration.Install();
                _statusLabel.Text = "Installed right-click 'Sanitize & Share via MetaGuard' + Windows SendTo shortcut.";
            }
            _shellToggleBtn.Text = ShellButtonText();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Shell Integration Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async void PickFiles()
    {
        using var ofd = new OpenFileDialog
        {
            Multiselect = true,
            Title = "Select files for MetaGuard Zero-Transit OS Mediation",
            Filter = "Supported Media & Docs|*.jpg;*.jpeg;*.png;*.webp;*.gif;*.wav;*.svg;*.pdf;*.docx;*.pptx;*.xlsx;*.mp4;*.mov;*.m4a|All Files|*.*"
        };

        if (ofd.ShowDialog(this) == DialogResult.OK && ofd.FileNames.Length > 0)
            await MediatePathsAsync(ofd.FileNames, "windows-file-picker");
    }

    private async Task MediatePathsAsync(string[] paths, string channel)
    {
        var validPaths = paths.Where(File.Exists).ToList();
        if (validPaths.Count == 0)
        {
            _statusLabel.Text = "No readable input files found.";
            return;
        }

        _statusLabel.Text = $"Ingesting {validPaths.Count} file(s) into isolated volatile memory...";
        _copyClipboardBtn.Enabled = false;
        _saveAllBtn.Enabled = false;

        var inputs = new List<OsMediationInput>(validPaths.Count);
        foreach (var path in validPaths)
        {
            var bytes = await File.ReadAllBytesAsync(path);
            inputs.Add(new OsMediationInput
            {
                FileName = Path.GetFileName(path),
                ContentType = FileSanitizerService.InferContentType(Path.GetExtension(path).ToLowerInvariant()),
                Payload = bytes,
                SourceChannel = channel
            });
        }

        var opts = OsMediationService.CreateDefaultMediationOptions();
        opts.EnableTier3Normalization = _tier3Box.Checked;

        var (batch, items) = await Task.Run(() => _mediator.MediateBatchAsync(inputs, opts, channel));
        _mediatedItems.Clear();
        _mediatedItems.AddRange(items);

        _statusLabel.Text = $"Zero-Transit Mediation complete ({batch.MediationMode}) in {batch.TotalLatencyMs:F2} ms — ready for Safe Dispatch.";
        _metricsLabel.Text = $"Mean PRI: {batch.MeanBeforePri:F1} -> {batch.MeanAfterPri:F1}  |  PER: {batch.MeanPerPercent:F1}%  |  Usability: {batch.MeanUsabilityScore:F1}%  |  Tamper Flags: {batch.TamperedFilesCount}";
        _metricsLabel.ForeColor = batch.TamperedFilesCount > 0 ? Color.FromArgb(251, 191, 36) : Color.FromArgb(52, 211, 153);

        var sb = new StringBuilder();
        sb.AppendLine($"Mode: {batch.MediationMode} | Source: {batch.SourceChannel} | T_transit = 0 ({batch.ZeroTransitVerified})");
        sb.AppendLine(new string('=', 88));

        foreach (var a in batch.Assets)
        {
            sb.AppendLine($"Asset      : {a.FileName} -> {a.SanitizedFileName}");
            sb.AppendLine($"Engine     : {a.EngineUsed} | VolatileRAM={a.VolatileMemoryOnly} | Latency={a.ProcessingLatencyMs:F2}ms (Parse {a.ParsingLatencyMs:F2} / Tamper {a.TamperAuditLatencyMs:F2} / Clean {a.SanitizeLatencyMs:F2} / Verify {a.VerifyLatencyMs:F2})");
            sb.AppendLine($"PRI Score  : {a.BeforePri:F1} ({a.BeforeRiskBand}) -> {a.AfterPri:F1} ({a.AfterRiskBand})  |  PER = {a.PrivacyExposureReductionPercent:F1}%");
            sb.AppendLine($"Usability  : {a.Usability.CompositeUsabilityScore:F1}% (ICC={a.Usability.ColorProfilePreserved}, Orient={a.Usability.OrientationPreserved}, PDF/UA={a.Usability.PdfAccessibilityPreserved}, OpenXML={a.Usability.OpenXmlIntegrityPreserved})");
            if (a.BeforeReport.RiskClusters.Count > 0)
                sb.AppendLine($"Clusters   : {string.Join("; ", a.BeforeReport.RiskClusters.Select(c => $"{c.ClusterId}(beta={c.Beta:F1}, +{c.SynergyContribution:F1})"))}");
            if (a.TamperAudit.IsTampered)
            {
                sb.AppendLine($"TAMPER FLAG: {a.TamperAudit.FlaggedRulesCount} forensic anomaly detected!");
                foreach (var flag in a.TamperAudit.Flags)
                    sb.AppendLine($"   [!] {flag.RuleId} ({flag.RuleName}): {flag.Evidence}");
            }
            sb.AppendLine($"Tier 1 Purged ({a.RemovedFields.Count})     : {string.Join(", ", a.RemovedFields.Select(f => f.NormalizedKey))}");
            sb.AppendLine($"Tier 3 Generalized ({a.GeneralizedFields.Count}): {string.Join(", ", a.GeneralizedFields.Select(f => $"{f.NormalizedKey}->{f.GeneralizedValue}"))}");
            sb.AppendLine($"Utility/Low Kept ({a.KeptFields.Count})  : {string.Join(", ", a.KeptFields.Select(f => f.NormalizedKey))}");
            sb.AppendLine($"Remaining Sensitive      : {a.RemainingSensitiveFields.Count}");
            sb.AppendLine(new string('-', 88));
        }

        if (batch.Errors.Count > 0)
        {
            sb.AppendLine("Errors:");
            foreach (var e in batch.Errors) sb.AppendLine($"  * {e}");
        }

        _detailsBox.Text = sb.ToString();
        _copyClipboardBtn.Enabled = _mediatedItems.Count > 0;
        _saveAllBtn.Enabled = _mediatedItems.Count > 0;
    }

    private void CopyCleanToClipboard()
    {
        if (_mediatedItems.Count == 0) return;

        CleanupStagedFiles();
        var stagingDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MetaGuard",
            "CleanDispatch",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stagingDir);

        var drops = new StringCollection();
        foreach (var (res, bytes) in _mediatedItems)
        {
            var destPath = Path.Combine(stagingDir, res.SanitizedFileName);
            File.WriteAllBytes(destPath, bytes);
            _stagedPaths.Add(destPath);
            drops.Add(destPath);
        }

        Clipboard.SetFileDropList(drops);
        _statusLabel.Text = $"Safe Dispatch ready: copied {drops.Count} cleaned file(s) to Windows Clipboard (Ctrl+V into any chat/mail/cloud app).";
    }

    private void SaveCleanCopies()
    {
        if (_mediatedItems.Count == 0) return;
        if (_mediatedItems.Count == 1)
        {
            var (res, bytes) = _mediatedItems[0];
            using var sfd = new SaveFileDialog
            {
                FileName = res.SanitizedFileName,
                Title = "Save Sanitized File"
            };
            if (sfd.ShowDialog(this) == DialogResult.OK)
            {
                File.WriteAllBytes(sfd.FileName, bytes);
                _statusLabel.Text = $"Saved clean copy to {sfd.FileName}";
            }
            return;
        }

        using var fbd = new FolderBrowserDialog { Description = "Select folder for sanitized batch output" };
        if (fbd.ShowDialog(this) == DialogResult.OK)
        {
            foreach (var (res, bytes) in _mediatedItems)
                File.WriteAllBytes(Path.Combine(fbd.SelectedPath, res.SanitizedFileName), bytes);
            _statusLabel.Text = $"Saved {_mediatedItems.Count} clean files to {fbd.SelectedPath}";
        }
    }

    private void CleanupStagedFiles()
    {
        foreach (var p in _stagedPaths)
        {
            try
            {
                if (File.Exists(p)) File.Delete(p);
                var dir = Path.GetDirectoryName(p);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                    Directory.Delete(dir);
            }
            catch { }
        }
        _stagedPaths.Clear();
    }
}
