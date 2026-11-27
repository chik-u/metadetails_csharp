using System.Text;
using Android.App;
using Android.Content;
using Android.Graphics;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Widget;
using MetaDetective.Api.MetaCore;
using Color = Android.Graphics.Color;
using Orientation = Android.Widget.Orientation;

namespace MetaGuard.Android;

/// <summary>
/// Intercepts Android ACTION_SEND and ACTION_SEND_MULTIPLE sharing intents, ingests
/// shared content:// URIs into volatile memory, runs MetaGuard's Tamper Audit + PRI +
/// Three-Tier Selective Sanitization locally, and dispatches clean URIs via MetaGuardContentProvider.
/// </summary>
[Activity(
    Name = "com.metaguard.mediator.ShareMediatorActivity",
    Label = "MetaGuard Safe Share",
    MainLauncher = true,
    Exported = true)]
[IntentFilter(
    new[] { Intent.ActionSend, Intent.ActionSendMultiple },
    Categories = new[] { Intent.CategoryDefault },
    DataMimeTypes = new[]
    {
        "image/*",
        "video/*",
        "audio/*",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "*/*"
    })]
public sealed class ShareMediatorActivity : Activity
{
    private const int PickFilesRequestCode = 7001;

    private readonly OsMediationService _mediator;
    private readonly List<(MediatedAssetResult Result, byte[] Bytes)> _mediatedItems = new();
    private TextView _headerStatus = null!;
    private TextView _reportView = null!;
    private CheckBox _tier3Check = null!;
    private Button _dispatchButton = null!;

    public ShareMediatorActivity()
    {
        var engine = new MetaCoreEngine();
        var extractor = new MetadataExtractorService();
        var sanitizer = new FileSanitizerService(engine, extractor);
        _mediator = new OsMediationService(engine, extractor, sanitizer);
    }

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        BuildUi();
        _ = HandleIntentAsync(Intent);
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Intent = intent;
        _ = HandleIntentAsync(intent);
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        if (requestCode == PickFilesRequestCode && resultCode == Result.Ok && data != null)
        {
            var uris = ExtractIncomingUris(data);
            _ = ProcessUrisAsync(uris, "android-document-picker");
        }
    }

    private void BuildUi()
    {
        var scroll = new ScrollView(this);
        scroll.SetBackgroundColor(Color.ParseColor("#0F172A"));
        scroll.SetFitsSystemWindows(true);

        var root = new LinearLayout(this)
        {
            Orientation = Orientation.Vertical
        };
        int pad = Dp(16);
        root.SetPadding(pad, Dp(28), pad, Dp(24));

        var title = new TextView(this)
        {
            Text = "MetaGuard OS Mediation Layer",
            TextSize = 20f
        };
        title.SetTypeface(Typeface.DefaultBold, TypefaceStyle.Bold);
        title.SetTextColor(Color.ParseColor("#F8FAFC"));

        var subtitle = new TextView(this)
        {
            Text = "Zero-Transit In-Memory Share Sanitizer (T_transit = 0 | Offline)",
            TextSize = 12.5f
        };
        subtitle.SetTextColor(Color.ParseColor("#38BDF8"));
        subtitle.SetPadding(0, Dp(4), 0, Dp(12));

        _tier3Check = new CheckBox(this)
        {
            Text = "Enable Tier 3 Generalization (Month/Year + Standard Software)",
            Checked = true
        };
        _tier3Check.SetTextColor(Color.ParseColor("#CBD5E1"));

        var pickBtn = new Button(this)
        {
            Text = "Pick Media / PDF / DOCX to Mediate Locally"
        };
        pickBtn.SetBackgroundColor(Color.ParseColor("#1E293B"));
        pickBtn.SetTextColor(Color.ParseColor("#E2E8F0"));
        pickBtn.Click += (_, _) =>
        {
            var picker = new Intent(Intent.ActionOpenDocument);
            picker.AddCategory(Intent.CategoryOpenable);
            picker.SetType("*/*");
            picker.PutExtra(Intent.ExtraAllowMultiple, true);
#pragma warning disable CS0618
            StartActivityForResult(picker, PickFilesRequestCode);
#pragma warning restore CS0618
        };

        _headerStatus = new TextView(this)
        {
            Text = "Ready for ACTION_SEND / ACTION_SEND_MULTIPLE interception.",
            TextSize = 14f
        };
        _headerStatus.SetTextColor(Color.ParseColor("#E2E8F0"));
        _headerStatus.SetPadding(0, Dp(14), 0, Dp(8));

        _dispatchButton = new Button(this)
        {
            Text = "Safe Dispatch (Open OS Share Sheet)",
            Enabled = false
        };
        _dispatchButton.SetBackgroundColor(Color.ParseColor("#059669"));
        _dispatchButton.SetTextColor(Color.White);
        _dispatchButton.Click += (_, _) => DispatchCleanAssets();

        _reportView = new TextView(this)
        {
            Text = "Share any photo, video, PDF, or Office file to MetaGuard from another app to sanitize it in volatile RAM prior to delivery.",
            TextSize = 12.5f
        };
        _reportView.SetTextColor(Color.ParseColor("#94A3B8"));
        _reportView.SetTypeface(Typeface.Monospace, TypefaceStyle.Normal);
        _reportView.SetPadding(0, Dp(14), 0, Dp(12));

        root.AddView(title);
        root.AddView(subtitle);
        root.AddView(_tier3Check);
        root.AddView(pickBtn);
        root.AddView(_headerStatus);
        root.AddView(_dispatchButton);
        root.AddView(_reportView);

        scroll.AddView(root);
        SetContentView(scroll);
    }

    private async Task HandleIntentAsync(Intent? intent)
    {
        if (intent == null) return;
        var action = intent.Action;
        if (action != Intent.ActionSend && action != Intent.ActionSendMultiple) return;

        var uris = ExtractIncomingUris(intent);
        var channel = action == Intent.ActionSendMultiple
            ? "android-action-send-multiple"
            : "android-action-send";
        await ProcessUrisAsync(uris, channel);
    }

    private List<global::Android.Net.Uri> ExtractIncomingUris(Intent intent)
    {
        var list = new List<global::Android.Net.Uri>();

        if (intent.Action == Intent.ActionSendMultiple)
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(33))
            {
                var arr = intent.GetParcelableArrayListExtra(Intent.ExtraStream, Java.Lang.Class.FromType(typeof(global::Android.Net.Uri)));
                if (arr != null)
                {
                    foreach (var item in arr)
                    {
                        if (item is global::Android.Net.Uri u) list.Add(u);
                    }
                }
            }
            else
            {
#pragma warning disable CA1422, CS0618
                var arr = intent.GetParcelableArrayListExtra(Intent.ExtraStream);
#pragma warning restore CA1422, CS0618
                if (arr != null)
                {
                    foreach (var item in arr)
                    {
                        if (item is global::Android.Net.Uri u) list.Add(u);
                    }
                }
            }
        }
        else if (intent.Action == Intent.ActionSend)
        {
            global::Android.Net.Uri? single = OperatingSystem.IsAndroidVersionAtLeast(33)
                ? intent.GetParcelableExtra(Intent.ExtraStream, Java.Lang.Class.FromType(typeof(global::Android.Net.Uri))) as global::Android.Net.Uri
                : GetLegacyParcelableUri(intent);
            if (single != null) list.Add(single);
        }

        if (list.Count == 0 && intent.ClipData != null)
        {
            for (int i = 0; i < intent.ClipData.ItemCount; i++)
            {
                var u = intent.ClipData.GetItemAt(i)?.Uri;
                if (u != null) list.Add(u);
            }
        }

        if (list.Count == 0 && intent.Data != null)
            list.Add(intent.Data);

        return list;
    }

    private static global::Android.Net.Uri? GetLegacyParcelableUri(Intent intent)
    {
#pragma warning disable CA1422, CS0618
        return intent.GetParcelableExtra(Intent.ExtraStream) as global::Android.Net.Uri;
#pragma warning restore CA1422, CS0618
    }

    private async Task ProcessUrisAsync(List<global::Android.Net.Uri> uris, string channel)
    {
        if (uris.Count == 0)
        {
            RunOnUiThread(() => _headerStatus.Text = "No binary content:// URIs found in share intent.");
            return;
        }

        RunOnUiThread(() =>
        {
            _dispatchButton.Enabled = false;
            _headerStatus.Text = $"Ingesting {uris.Count} shared asset(s) into volatile RAM...";
        });

        try
        {
            var inputs = new List<OsMediationInput>(uris.Count);
            foreach (var uri in uris)
            {
                var (name, mime) = ResolveDisplayNameAndMime(uri);
                await using var inputStream = ContentResolver?.OpenInputStream(uri)
                    ?? throw new IOException($"Cannot read shared URI: {uri}");
                using var mem = new MemoryStream();
                await inputStream.CopyToAsync(mem);

                inputs.Add(new OsMediationInput
                {
                    FileName = name,
                    ContentType = mime,
                    Payload = mem.ToArray(),
                    SourceChannel = channel
                });
            }

            var options = OsMediationService.CreateDefaultMediationOptions();
            options.EnableTier3Normalization = _tier3Check.Checked;

            var (batch, items) = await Task.Run(() => _mediator.MediateBatchAsync(inputs, options, channel));
            _mediatedItems.Clear();
            _mediatedItems.AddRange(items);

            var sb = new StringBuilder();
            sb.AppendLine($"Mode: {batch.MediationMode} | Channel: {batch.SourceChannel}");
            sb.AppendLine($"Zero-Transit Verified: {batch.ZeroTransitVerified} | Total Latency: {batch.TotalLatencyMs:F2} ms");
            sb.AppendLine($"Mean PRI: {batch.MeanBeforePri:F1} -> {batch.MeanAfterPri:F1} (PER: {batch.MeanPerPercent:F1}%)");
            sb.AppendLine($"Mean Usability Retained: {batch.MeanUsabilityScore:F1}% | Tampered Files: {batch.TamperedFilesCount}");
            sb.AppendLine(new string('-', 42));

            foreach (var asset in batch.Assets)
            {
                sb.AppendLine($"File: {asset.FileName} -> {asset.SanitizedFileName}");
                sb.AppendLine($"  Engine: {asset.EngineUsed} | RAM-Only: {asset.VolatileMemoryOnly}");
                sb.AppendLine($"  PRI: {asset.BeforePri:F1} -> {asset.AfterPri:F1} ({asset.BeforeRiskBand} -> {asset.AfterRiskBand})");
                sb.AppendLine($"  Removed: {asset.RemovedFields.Count} | Generalized: {asset.GeneralizedFields.Count} | Kept Utility: {asset.KeptFields.Count}");
                sb.AppendLine($"  Usability: {asset.Usability.CompositeUsabilityScore:F1}% | Remaining Sensitive: {asset.RemainingSensitiveFields.Count}");
                if (asset.TamperAudit.IsTampered)
                {
                    sb.AppendLine($"  [TAMPER ALERT] {asset.TamperAudit.FlaggedRulesCount} rule(s):");
                    foreach (var f in asset.TamperAudit.Flags)
                        sb.AppendLine($"    * {f.RuleName}: {f.Evidence}");
                }
                sb.AppendLine();
            }

            if (batch.Errors.Count > 0)
            {
                sb.AppendLine("Errors:");
                foreach (var err in batch.Errors) sb.AppendLine($"  - {err}");
            }

            RunOnUiThread(() =>
            {
                _headerStatus.Text = _mediatedItems.Count > 0
                    ? $"Mediated {_mediatedItems.Count} asset(s) in {batch.TotalLatencyMs:F1} ms (PER {batch.MeanPerPercent:F1}%)."
                    : "Mediation failed for selected asset(s).";
                _reportView.Text = sb.ToString();
                _dispatchButton.Enabled = _mediatedItems.Count > 0;
            });
        }
        catch (Exception ex)
        {
            RunOnUiThread(() => _headerStatus.Text = $"Mediation error: {ex.Message}");
        }
    }

    private void DispatchCleanAssets()
    {
        if (_mediatedItems.Count == 0) return;

        var outboundUris = new List<global::Android.Net.Uri>();
        foreach (var (res, bytes) in _mediatedItems)
            outboundUris.Add(MetaGuardContentProvider.StoreInMemory(bytes, res.SanitizedFileName, res.ContentType));

        Intent shareIntent;
        if (outboundUris.Count == 1)
        {
            shareIntent = new Intent(Intent.ActionSend);
            shareIntent.SetType(_mediatedItems[0].Result.ContentType);
            shareIntent.PutExtra(Intent.ExtraStream, outboundUris[0]);
        }
        else
        {
            shareIntent = new Intent(Intent.ActionSendMultiple);
            shareIntent.SetType("*/*");
            shareIntent.PutParcelableArrayListExtra(Intent.ExtraStream, outboundUris.Cast<IParcelable>().ToList());
        }

        var clip = ClipData.NewRawUri("MetaGuard Sanitized Output", outboundUris[0]);
        for (int i = 1; i < outboundUris.Count; i++)
            clip?.AddItem(new ClipData.Item(outboundUris[i]));
        shareIntent.ClipData = clip;
        shareIntent.AddFlags(ActivityFlags.GrantReadUriPermission);
        var chooser = Intent.CreateChooser(shareIntent, "Dispatch Clean File (MetaGuard Safe Share)")!;
        if (OperatingSystem.IsAndroidVersionAtLeast(24))
        {
            var selfComponent = ComponentName;
            if (selfComponent != null)
                chooser.PutExtra(Intent.ExtraExcludeComponents, new IParcelable[] { selfComponent });
        }

        StartActivity(chooser);
    }

    private (string Name, string Mime) ResolveDisplayNameAndMime(global::Android.Net.Uri uri)
    {
        var mime = ContentResolver?.GetType(uri) ?? "application/octet-stream";
        string? name = null;

        using (var cursor = ContentResolver?.Query(uri, new[] { IOpenableColumns.DisplayName }, null, null, null))
        {
            if (cursor != null && cursor.MoveToFirst())
            {
                int idx = cursor.GetColumnIndex(IOpenableColumns.DisplayName);
                if (idx >= 0) name = cursor.GetString(idx);
            }
        }

        name ??= System.IO.Path.GetFileName(uri.Path ?? $"shared_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");
        if (string.IsNullOrWhiteSpace(System.IO.Path.GetExtension(name)) && mime.Contains('/'))
        {
            var sub = mime.Split('/')[^1].Split(';')[0].Replace("jpeg", "jpg");
            name = $"{name}.{sub}";
        }

        return (name, mime);
    }

    private int Dp(int dp) => (int)Math.Round(dp * (Resources?.DisplayMetrics?.Density ?? 1f));
}
