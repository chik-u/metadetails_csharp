using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Pre-sanitization heuristic tamper detection inspecting chronological anomalies,
/// editing software discrepancies, incomplete coordinate clusters, and solar time divergence.
/// </summary>
public static class TamperDetectionService
{
    private static readonly string[] EditorSignatures =
    [
        "photoshop", "gimp", "lightroom", "affinity", "canva", "photopea",
        "snapseed", "pixlr", "corel", "paint.net", "illustrator", "inkscape", "exiftool"
    ];

    private static readonly string[] CreateTimeKeys =
    [
        "DateTimeOriginal", "CreateDate", "CreationDate", "ContentCreateDate", "DateTimeDigitized"
    ];

    private static readonly string[] ModifyTimeKeys =
    [
        "ModifyDate", "ModDate", "MetadataDate"
    ];

    public static TamperAuditReport Audit(JsonObject metadata)
    {
        var map = BuildNormalizedLookup(metadata);
        var flags = new List<TamperFlag>();

        CheckChronologicalAnomaly(map, flags);
        CheckSoftwareDiscrepancy(map, flags);
        CheckClusterIncompleteness(map, flags);
        CheckSolarTimeDivergence(map, flags);

        return new TamperAuditReport
        {
            IsTampered = flags.Count > 0,
            FlaggedRulesCount = flags.Count,
            Flags = flags
        };
    }

    private static Dictionary<string, string> BuildNormalizedLookup(JsonObject metadata)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in metadata)
        {
            if (kvp.Value == null) continue;
            var str = kvp.Value.ToString();
            if (string.IsNullOrWhiteSpace(str)) continue;

            var colon = kvp.Key.IndexOf(':');
            var norm = colon > 0 && colon < kvp.Key.Length - 1 ? kvp.Key[(colon + 1)..] : kvp.Key;
            map.TryAdd(kvp.Key, str);
            map.TryAdd(norm, str);
        }
        return map;
    }

    private static void CheckChronologicalAnomaly(Dictionary<string, string> map, List<TamperFlag> flags)
    {
        DateTime? tCreate = null;
        string? createKey = null;
        foreach (var k in CreateTimeKeys)
        {
            if (map.TryGetValue(k, out var raw) && TryParseMetadataDateTime(raw, out var dt))
            {
                tCreate = dt;
                createKey = k;
                break;
            }
        }

        DateTime? tMod = null;
        string? modKey = null;
        foreach (var k in ModifyTimeKeys)
        {
            if (map.TryGetValue(k, out var raw) && TryParseMetadataDateTime(raw, out var dt))
            {
                tMod = dt;
                modKey = k;
                break;
            }
        }

        if (tCreate.HasValue && tMod.HasValue && tMod.Value < tCreate.Value.AddSeconds(-1))
        {
            flags.Add(new TamperFlag
            {
                RuleId = "tau_chron",
                RuleName = "Chronological Anomaly",
                Severity = "High",
                Evidence = $"{modKey} ({tMod.Value:yyyy-MM-dd HH:mm:ss}) precedes {createKey} ({tCreate.Value:yyyy-MM-dd HH:mm:ss})."
            });
        }
    }

    private static void CheckSoftwareDiscrepancy(Dictionary<string, string> map, List<TamperFlag> flags)
    {
        var softwareCandidates = new[] { "Software", "ProcessingSoftware", "CreatorTool", "Producer", "Application" }
            .Where(k => map.TryGetValue(k, out _))
            .Select(k => (Key: k, Val: map[k]))
            .ToList();

        var editorHit = softwareCandidates
            .FirstOrDefault(s => EditorSignatures.Any(sig => s.Val.Contains(sig, StringComparison.OrdinalIgnoreCase)));

        bool hasCameraClaim =
            map.ContainsKey("Make") && map.ContainsKey("Model") &&
            (map.ContainsKey("ExposureTime") || map.ContainsKey("ISO") || map.ContainsKey("FNumber") ||
             (map.TryGetValue("DigitalSourceType", out var dst) && dst.Contains("capture", StringComparison.OrdinalIgnoreCase)));

        if (!string.IsNullOrEmpty(editorHit.Key) && hasCameraClaim)
        {
            flags.Add(new TamperFlag
            {
                RuleId = "tau_soft",
                RuleName = "Software Discrepancy",
                Severity = "Medium",
                Evidence = $"Editing suite signature ({editorHit.Key}='{editorHit.Val}') co-occurs with direct camera capture parameters ({map["Make"]} {map["Model"]})."
            });
        }
    }

    private static void CheckClusterIncompleteness(Dictionary<string, string> map, List<TamperFlag> flags)
    {
        bool hasLat = map.ContainsKey("GPSLatitude") || map.ContainsKey("Latitude");
        bool hasLon = map.ContainsKey("GPSLongitude") || map.ContainsKey("Longitude");
        bool hasLatRef = map.ContainsKey("GPSLatitudeRef");
        bool hasLonRef = map.ContainsKey("GPSLongitudeRef");

        if (hasLat ^ hasLon)
        {
            flags.Add(new TamperFlag
            {
                RuleId = "tau_clust",
                RuleName = "Cluster Incompleteness",
                Severity = "High",
                Evidence = hasLat
                    ? "GPSLatitude is embedded without a paired GPSLongitude coordinate."
                    : "GPSLongitude is embedded without a paired GPSLatitude coordinate."
            });
            return;
        }

        if ((hasLatRef && !hasLat) || (hasLonRef && !hasLon))
        {
            flags.Add(new TamperFlag
            {
                RuleId = "tau_clust",
                RuleName = "Cluster Incompleteness",
                Severity = "High",
                Evidence = "Orphaned GPS hemisphere reference tag present without corresponding coordinate value."
            });
        }
    }

    private static void CheckSolarTimeDivergence(Dictionary<string, string> map, List<TamperFlag> flags)
    {
        if (!map.TryGetValue("GPSLongitude", out var lonRaw) && !map.TryGetValue("Longitude", out lonRaw))
            return;

        map.TryGetValue("GPSLongitudeRef", out var lonRef);
        if (!TryParseLongitude(lonRaw, lonRef, out double lonDeg))
            return;

        if (Math.Abs(lonDeg) > 180.0 ||
            (map.TryGetValue("GPSLatitude", out var latRaw) &&
             TryParseLongitude(latRaw, map.GetValueOrDefault("GPSLatitudeRef"), out double latDeg) &&
             Math.Abs(latDeg) > 90.0))
        {
            flags.Add(new TamperFlag
            {
                RuleId = "tau_geo",
                RuleName = "Solar Time / Coordinate Divergence",
                Severity = "Critical",
                Evidence = $"Out-of-bounds geographic coordinate detected (longitude={lonDeg:F4})."
            });
            return;
        }

        // Eq. (9): Delta t_solar = floor(Longitude / 15 deg) hours
        double solarOffsetHours = Math.Floor(lonDeg / 15.0);

        // Compare GPSTimeStamp (UTC) + solarOffsetHours against embedded local capture timestamp
        DateTime? localCapture = null;
        foreach (var k in CreateTimeKeys)
        {
            if (map.TryGetValue(k, out var raw) && TryParseMetadataDateTime(raw, out var dt))
            {
                localCapture = dt;
                break;
            }
        }

        if (localCapture.HasValue && TryExtractGpsUtcTimeOfDay(map, out TimeSpan gpsUtcTime))
        {
            double solarLocalHours = Modulo24(gpsUtcTime.TotalHours + solarOffsetHours);
            double embeddedLocalHours = localCapture.Value.TimeOfDay.TotalHours;
            double diffHours = ShortestHourDistance(solarLocalHours, embeddedLocalHours);

            if (diffHours > 2.5)
            {
                flags.Add(new TamperFlag
                {
                    RuleId = "tau_geo",
                    RuleName = "Solar Time Divergence",
                    Severity = "Critical",
                    Evidence = $"Solar offset ({solarOffsetHours:+0;-0;0}h at lon {lonDeg:F2}°) implies local hour {solarLocalHours:F1}h from GPS UTC {gpsUtcTime:hh\\:mm}, diverging {diffHours:F1}h (>2.5h) from embedded capture hour {embeddedLocalHours:F1}h."
                });
                return;
            }
        }

        // Fallback when OffsetTimeOriginal/OffsetTime is recorded alongside Longitude
        if ((map.TryGetValue("OffsetTimeOriginal", out var offRaw) || map.TryGetValue("OffsetTime", out offRaw)) &&
            TryParseUtcOffsetHours(offRaw, out double offsetHours))
        {
            double diff = ShortestHourDistance(Modulo24(solarOffsetHours), Modulo24(offsetHours));
            if (diff > 2.5)
            {
                flags.Add(new TamperFlag
                {
                    RuleId = "tau_geo",
                    RuleName = "Solar Time Divergence",
                    Severity = "High",
                    Evidence = $"Embedded UTC offset ({offsetHours:+0.#;-0.#;0}h) diverges {diff:F1}h (>2.5h) from solar offset ({solarOffsetHours:+0;-0;0}h at lon {lonDeg:F2}°)."
                });
            }
        }
    }

    public static bool TryParseMetadataDateTime(string raw, out DateTime dt)
    {
        dt = default;
        var s = raw.Trim();
        if (s.StartsWith("D:", StringComparison.OrdinalIgnoreCase))
        {
            var m = Regex.Match(s, @"^D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})");
            if (m.Success &&
                int.TryParse(m.Groups[1].Value, out int y) &&
                int.TryParse(m.Groups[2].Value, out int mo) &&
                int.TryParse(m.Groups[3].Value, out int d) &&
                int.TryParse(m.Groups[4].Value, out int h) &&
                int.TryParse(m.Groups[5].Value, out int mi) &&
                int.TryParse(m.Groups[6].Value, out int se))
            {
                try { dt = new DateTime(y, mo, d, h, mi, se, DateTimeKind.Unspecified); return true; }
                catch { return false; }
            }
        }

        string[] exifFormats =
        [
            "yyyy:MM:dd HH:mm:ss",
            "yyyy:MM:dd HH:mm:ss.fff",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-ddTHH:mm:ss",
            "yyyy-MM-ddTHH:mm:ssZ",
            "yyyy-MM-ddTHH:mm:sszzz"
        ];

        if (DateTime.TryParseExact(s, exifFormats, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AllowWhiteSpaces, out dt))
            return true;

        return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out dt);
    }

    private static bool TryExtractGpsUtcTimeOfDay(Dictionary<string, string> map, out TimeSpan timeOfDay)
    {
        timeOfDay = default;
        if (map.TryGetValue("GPSTimeStamp", out var ts))
        {
            // Forms: "12:34:56", "12, 34, 56", "[12, 34, 56]"
            var nums = Regex.Matches(ts, @"\d+(?:\.\d+)?")
                .Select(m => double.Parse(m.Value, CultureInfo.InvariantCulture))
                .ToList();
            if (nums.Count >= 2)
            {
                int h = (int)nums[0];
                int min = (int)nums[1];
                int sec = nums.Count >= 3 ? (int)Math.Round(nums[2]) : 0;
                if (h is >= 0 and < 24 && min is >= 0 and < 60 && sec is >= 0 and <= 60)
                {
                    timeOfDay = new TimeSpan(h, min, Math.Min(59, sec));
                    return true;
                }
            }
        }

        if (map.TryGetValue("GPSDateTime", out var gdt) && TryParseMetadataDateTime(gdt, out var dt))
        {
            timeOfDay = dt.TimeOfDay;
            return true;
        }

        return false;
    }

    public static bool TryParseLongitude(string raw, string? refHemisphere, out double degrees)
    {
        degrees = 0;
        var s = raw.Trim();
        var hemi = !string.IsNullOrWhiteSpace(refHemisphere) ? refHemisphere.Trim().ToUpperInvariant() : string.Empty;
        if (s.EndsWith("W", StringComparison.OrdinalIgnoreCase) || s.EndsWith("S", StringComparison.OrdinalIgnoreCase))
            hemi = s[^1].ToString().ToUpperInvariant();
        else if (s.EndsWith("E", StringComparison.OrdinalIgnoreCase) || s.EndsWith("N", StringComparison.OrdinalIgnoreCase))
            hemi = s[^1].ToString().ToUpperInvariant();

        var matches = Regex.Matches(s, @"-?\d+(?:\.\d+)?");
        if (matches.Count == 0) return false;

        if (matches.Count == 1)
        {
            if (!double.TryParse(matches[0].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out degrees))
                return false;
        }
        else
        {
            double d = double.Parse(matches[0].Value, CultureInfo.InvariantCulture);
            double m = double.Parse(matches[1].Value, CultureInfo.InvariantCulture);
            double sec = matches.Count >= 3 ? double.Parse(matches[2].Value, CultureInfo.InvariantCulture) : 0.0;
            double sign = d < 0 ? -1.0 : 1.0;
            degrees = sign * (Math.Abs(d) + m / 60.0 + sec / 3600.0);
        }

        if (hemi is "W" or "S")
            degrees = -Math.Abs(degrees);
        else if (hemi is "E" or "N")
            degrees = Math.Abs(degrees);

        return true;
    }

    private static bool TryParseUtcOffsetHours(string raw, out double hours)
    {
        hours = 0;
        var m = Regex.Match(raw.Trim(), @"^([+-])(\d{1,2}):?(\d{2})$");
        if (!m.Success) return false;
        double sign = m.Groups[1].Value == "-" ? -1.0 : 1.0;
        double h = double.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        double min = double.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture);
        hours = sign * (h + min / 60.0);
        return true;
    }

    private static double Modulo24(double h) => ((h % 24.0) + 24.0) % 24.0;

    private static double ShortestHourDistance(double a, double b)
    {
        double diff = Math.Abs(Modulo24(a) - Modulo24(b));
        return diff > 12.0 ? 24.0 - diff : diff;
    }
}
