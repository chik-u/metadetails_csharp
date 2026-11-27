using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Priority tier assigned by MetaCore to each extracted metadata detail.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MetaPriority
{
    /// <summary>Essential structural or decoding metadata required for file integrity (Kept).</summary>
    Required = 0,

    /// <summary>Benign technical metadata with negligible privacy risk (Kept by default).</summary>
    Low = 1,

    /// <summary>Privacy- or fingerprint-sensitive metadata (Removed).</summary>
    High = 2,

    /// <summary>Directly identifying, location, or high-risk PII metadata (Removed).</summary>
    Critical = 3
}

/// <summary>
/// Sanitization action determined for a metadata field.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MetaAction
{
    Keep,
    Remove
}

/// <summary>
/// Options controlling how MetaCore evaluates and sanitizes metadata.
/// </summary>
public class MetaSanitizeOptions
{
    public bool KeepRequired { get; set; } = true;
    public bool KeepLowPriority { get; set; } = true;
    public bool StrictMode { get; set; } = false;
    public List<string> KeepTags { get; set; } = new();
    public List<string> RemoveTags { get; set; } = new();
}

/// <summary>
/// A single metadata field enriched with MetaCore priority, category, and sanitization policy.
/// </summary>
public class ClassifiedMetadetail
{
    public string Key { get; set; } = string.Empty;
    public string NormalizedKey { get; set; } = string.Empty;
    public JsonNode? Value { get; set; }
    public MetaPriority Priority { get; set; }
    public int PriorityScore { get; set; }
    public string Category { get; set; } = string.Empty;
    public MetaAction Action { get; set; }
    public bool IsSensitive { get; set; }
    public bool IsRequired { get; set; }
    public bool IsEmbeddedWritable { get; set; }
    public bool IsRuntimeSynthetic { get; set; }
    public string Reason { get; set; } = string.Empty;
}

/// <summary>
/// Aggregated MetaCore priority and risk report for a file's metadata.
/// </summary>
public class MetaCoreReport
{
    public int TotalCount { get; set; }
    public int RequiredCount { get; set; }
    public int LowPriorityCount { get; set; }
    public int HighPriorityCount { get; set; }
    public int CriticalPriorityCount { get; set; }
    public int SensitiveCount { get; set; }
    public int KeptCount { get; set; }
    public int RemovedCount { get; set; }
    public string RiskLevel { get; set; } = "Clean";
    public List<ClassifiedMetadetail> Details { get; set; } = new();
    public List<string> KeptTags { get; set; } = new();
    public List<string> RemovedTags { get; set; } = new();
    public List<string> WritablePreserveTags { get; set; } = new();
}

/// <summary>
/// Complete sanitization result comparing metadata before and after cleaning.
/// </summary>
public class SanitizationResult
{
    public string FileName { get; set; } = string.Empty;
    public string SanitizedFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long OriginalSize { get; set; }
    public long SanitizedSize { get; set; }
    public long BytesRemoved { get; set; }
    public string EngineUsed { get; set; } = string.Empty;
    public string DownloadId { get; set; } = string.Empty;
    public string DownloadUrl { get; set; } = string.Empty;
    public MetaCoreReport BeforeReport { get; set; } = new();
    public MetaCoreReport AfterReport { get; set; } = new();
    public List<ClassifiedMetadetail> RemovedFields { get; set; } = new();
    public List<ClassifiedMetadetail> KeptFields { get; set; } = new();
    public List<ClassifiedMetadetail> RemainingSensitiveFields { get; set; } = new();
}
