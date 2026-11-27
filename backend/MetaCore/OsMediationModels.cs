namespace MetaDetective.Api.MetaCore;

public sealed class TamperFlag
{
    public string RuleId { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    public string Severity { get; set; } = "High";
    public string Evidence { get; set; } = string.Empty;
}

public sealed class TamperAuditReport
{
    public bool IsTampered { get; set; }
    public int FlaggedRulesCount { get; set; }
    public List<TamperFlag> Flags { get; set; } = new();
}

public sealed class UsabilityPreservationMetrics
{
    public bool HadColorProfile { get; set; }
    public bool ColorProfilePreserved { get; set; } = true;
    public bool HadOrientation { get; set; }
    public bool OrientationPreserved { get; set; } = true;
    public bool IsPdf { get; set; }
    public bool HadPdfAccessibilityTree { get; set; }
    public bool PdfAccessibilityPreserved { get; set; } = true;
    public bool IsOpenXml { get; set; }
    public bool OpenXmlIntegrityPreserved { get; set; } = true;
    public double CompositeUsabilityScore { get; set; } = 100.0;
}

/// <summary>
/// Input descriptor for the OS mediation layer (Android ACTION_SEND/ACTION_SEND_MULTIPLE,
/// Windows SendTo/Shell share, or Web Share Target).
/// </summary>
public sealed class OsMediationInput
{
    public string FileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public byte[] Payload { get; set; } = [];
    public string SourceChannel { get; set; } = "os-mediation";
}

/// <summary>
/// Per-asset result produced entirely within volatile client/process memory.
/// </summary>
public sealed class MediatedAssetResult
{
    public string FileName { get; set; } = string.Empty;
    public string SanitizedFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long OriginalSize { get; set; }
    public long SanitizedSize { get; set; }
    public long BytesRemoved { get; set; }
    public string EngineUsed { get; set; } = string.Empty;
    public string SourceChannel { get; set; } = string.Empty;
    public bool ZeroTransitVerified { get; set; }
    public bool VolatileMemoryOnly { get; set; }
    public double BeforePri { get; set; }
    public double AfterPri { get; set; }
    public double PrivacyExposureReductionPercent { get; set; }
    public string BeforeRiskBand { get; set; } = "Low Risk";
    public string AfterRiskBand { get; set; } = "Low Risk";
    public double ProcessingLatencyMs { get; set; }
    public double ParsingLatencyMs { get; set; }
    public double TamperAuditLatencyMs { get; set; }
    public double SanitizeLatencyMs { get; set; }
    public double VerifyLatencyMs { get; set; }
    public string DispatchId { get; set; } = string.Empty;
    public string DispatchUri { get; set; } = string.Empty;
    public TamperAuditReport TamperAudit { get; set; } = new();
    public UsabilityPreservationMetrics Usability { get; set; } = new();
    public MetaCoreReport BeforeReport { get; set; } = new();
    public MetaCoreReport AfterReport { get; set; } = new();
    public List<ClassifiedMetadetail> RemovedFields { get; set; } = new();
    public List<ClassifiedMetadetail> GeneralizedFields { get; set; } = new();
    public List<ClassifiedMetadetail> KeptFields { get; set; } = new();
    public List<ClassifiedMetadetail> RemainingSensitiveFields { get; set; } = new();
}

/// <summary>
/// Batch mediation outcome matching ACTION_SEND (1 item) or ACTION_SEND_MULTIPLE (N items).
/// </summary>
public sealed class OsMediationBatchResult
{
    public string MediationMode { get; set; } = "ACTION_SEND";
    public string SourceChannel { get; set; } = "os-mediation";
    public bool ZeroTransitVerified { get; set; } = true;
    public double TotalLatencyMs { get; set; }
    public double MeanBeforePri { get; set; }
    public double MeanAfterPri { get; set; }
    public double MeanPerPercent { get; set; }
    public double MeanUsabilityScore { get; set; }
    public int TamperedFilesCount { get; set; }
    public List<MediatedAssetResult> Assets { get; set; } = new();
    public List<string> Errors { get; set; } = new();
}
