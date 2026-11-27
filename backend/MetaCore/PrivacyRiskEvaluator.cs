namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Evaluates the non-linear Privacy Risk Index (PRI) bounded on [0, 100] with
/// synergistic quasi-identifier cluster multipliers and three-tier generalization helpers.
/// </summary>
public static class PrivacyRiskEvaluator
{
    public const double BetaGeoTime = 1.5;
    public const double BetaDeviceProfile = 1.3;
    public const double BetaDirectIdentity = 2.0;

    private static readonly HashSet<string> GeneralizedStandardMarkers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Standard Software",
        "Standard Office Application",
        "Standard PDF Generator",
        "Author"
    };

    private static readonly HashSet<string> LocationClusterKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "GPSLatitude", "GPSLongitude", "GPSPosition", "Latitude", "Longitude",
        "GPSCoordinates", "City", "Country", "Sub-location", "State", "Province-State"
    };

    private static readonly HashSet<string> GeoCoordClusterKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "GPSLatitude", "GPSLongitude", "GPSPosition", "Latitude", "Longitude", "GPSCoordinates"
    };

    private static readonly HashSet<string> TimestampClusterKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "DateTimeOriginal", "CreateDate", "ModifyDate", "CreationDate", "ModDate",
        "Creation Time", "GPSTimeStamp", "GPSDateTime", "TrackCreateDate", "MediaCreateDate",
        "ContentCreateDate", "DateCreated"
    };

    private static readonly HashSet<string> DeviceCoreKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Make", "Model", "CameraModelName", "LensModel", "Lens"
    };

    private static readonly HashSet<string> DeviceIdOrSoftwareKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "SerialNumber", "InternalSerialNumber", "BodySerialNumber", "LensSerialNumber",
        "CameraSerialNumber", "ImageUniqueID", "Software", "ProcessingSoftware", "MakerNotes", "MakerNote"
    };

    private static readonly HashSet<string> IdentityClusterKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "Author", "Artist", "Creator", "OwnerName", "CameraOwnerName", "LastModifiedBy",
        "By-line", "XPAuthor", "UserComment", "Comment", "Comments", "Company"
    };

    public static bool IsGeneralizedPlaceholderValue(string normalizedKey, string? rawVal)
    {
        if (string.IsNullOrWhiteSpace(rawVal)) return false;
        var v = rawVal.Trim();
        if (GeneralizedStandardMarkers.Contains(v)) return true;

        if (TimestampClusterKeys.Contains(normalizedKey))
        {
            // Month/year generalization formats: "YYYY-MM", "YYYY:MM", "YYYY:MM:01 00:00:00", "YYYY-MM-01T00:00:00Z", "D:YYYYMM"
            if (System.Text.RegularExpressions.Regex.IsMatch(
                    v,
                    @"^(\d{4}[-:]\d{2}(?:[-:]01(?:[ T]00:00:00Z?)?)?|D:\d{6}(?:01000000Z)?)$",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static string GeneralizeValue(string normalizedKey, string rawVal)
    {
        var v = rawVal.Trim();
        if (TimestampClusterKeys.Contains(normalizedKey))
        {
            var m = System.Text.RegularExpressions.Regex.Match(v, @"(?<!\d)(\d{4})[-:]?(\d{2})");
            if (m.Success)
            {
                var year = m.Groups[1].Value;
                var month = m.Groups[2].Value;
                if (normalizedKey.Equals("CreationDate", StringComparison.OrdinalIgnoreCase) ||
                    normalizedKey.Equals("ModDate", StringComparison.OrdinalIgnoreCase))
                {
                    return $"D:{year}{month}01000000Z";
                }
                if (v.Contains('T'))
                {
                    return $"{year}-{month}-01T00:00:00Z";
                }
                if (v.Contains(':'))
                {
                    return $"{year}:{month}:01 00:00:00";
                }
                return $"{year}-{month}";
            }
            return "Standard Date";
        }

        if (normalizedKey.Equals("Application", StringComparison.OrdinalIgnoreCase))
            return "Standard Office Application";

        if (normalizedKey.Equals("Producer", StringComparison.OrdinalIgnoreCase))
            return "Standard PDF Generator";

        return "Standard Software";
    }

    public static double AssignBaseWeight(
        string normalizedKey,
        string? rawValue,
        MetaPriority priority,
        string category,
        bool isRuntimeSynthetic)
    {
        if (isRuntimeSynthetic)
        {
            return normalizedKey.Equals("OCRText", StringComparison.OrdinalIgnoreCase) ? 9.5 : 0.0;
        }

        if (IsGeneralizedPlaceholderValue(normalizedKey, rawValue))
        {
            return 0.5;
        }

        if (priority == MetaPriority.Required)
            return 0.0;

        if (priority == MetaPriority.Low)
        {
            return category.Contains("Camera", StringComparison.OrdinalIgnoreCase) ? 1.5 : 1.0;
        }

        if (priority == MetaPriority.Critical)
        {
            if (LocationClusterKeys.Contains(normalizedKey) || category.Contains("Location", StringComparison.OrdinalIgnoreCase))
                return 10.0;
            if (normalizedKey.Contains("Serial", StringComparison.OrdinalIgnoreCase) ||
                normalizedKey.Equals("ImageUniqueID", StringComparison.OrdinalIgnoreCase) ||
                IdentityClusterKeys.Contains(normalizedKey))
                return 9.5;
            return 9.0;
        }

        // High priority: differentiate purgeable high-risk blocks (>= 7.0) from moderate Tier-3 candidates [4.0, 7.0)
        if (category.Contains("Preview", StringComparison.OrdinalIgnoreCase) ||
            category.Contains("MakerNotes", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("Thumbnail", StringComparison.OrdinalIgnoreCase) ||
            normalizedKey.Contains("MakerNote", StringComparison.OrdinalIgnoreCase))
        {
            return 8.0;
        }

        if (TimestampClusterKeys.Contains(normalizedKey) ||
            normalizedKey.StartsWith("OffsetTime", StringComparison.OrdinalIgnoreCase))
            return 5.0;

        if (category.Contains("Software", StringComparison.OrdinalIgnoreCase))
            return 4.5;

        if (DeviceCoreKeys.Contains(normalizedKey) || normalizedKey.StartsWith("Lens", StringComparison.OrdinalIgnoreCase))
            return 5.5;

        return 7.0;
    }

    public static (double Pri, string RiskBand, List<RiskClusterMatch> Clusters) EvaluatePri(
        IReadOnlyList<ClassifiedMetadetail> details)
    {
        // Only embedded attributes + flagged OCR content contribute to embedded file PRI.
        var active = details
            .Where(d => !d.IsRuntimeSynthetic || d.NormalizedKey.Equals("OCRText", StringComparison.OrdinalIgnoreCase))
            .ToList();

        double linearSum = active.Sum(d => d.BaseWeight);
        var clusters = new List<RiskClusterMatch>();

        var geoField = active.Where(d => GeoCoordClusterKeys.Contains(d.NormalizedKey) && d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();
        var timeField = active.Where(d => TimestampClusterKeys.Contains(d.NormalizedKey) && d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();

        if (geoField != null && timeField != null)
        {
            double synergy = BetaGeoTime * Math.Sqrt(geoField.BaseWeight * timeField.BaseWeight);
            clusters.Add(new RiskClusterMatch
            {
                ClusterId = "K_geo-time",
                Name = "Spatio-Temporal Tracking Cluster",
                Beta = BetaGeoTime,
                SynergyContribution = Math.Round(synergy, 2),
                InvolvedTags = [geoField.NormalizedKey, timeField.NormalizedKey]
            });
        }

        var devPrimary = active.Where(d => DeviceCoreKeys.Contains(d.NormalizedKey) && d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();
        var devSecondary = active.Where(d => DeviceIdOrSoftwareKeys.Contains(d.NormalizedKey) &&
                                             !d.NormalizedKey.Equals(devPrimary?.NormalizedKey, StringComparison.OrdinalIgnoreCase) &&
                                             d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();

        if (devPrimary != null && devSecondary != null)
        {
            double synergy = BetaDeviceProfile * Math.Sqrt(devPrimary.BaseWeight * devSecondary.BaseWeight);
            clusters.Add(new RiskClusterMatch
            {
                ClusterId = "K_device",
                Name = "Hardware & Toolchain Fingerprint Cluster",
                Beta = BetaDeviceProfile,
                SynergyContribution = Math.Round(synergy, 2),
                InvolvedTags = [devPrimary.NormalizedKey, devSecondary.NormalizedKey]
            });
        }

        var idField = active.Where(d => IdentityClusterKeys.Contains(d.NormalizedKey) && d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();
        var locField = active.Where(d => LocationClusterKeys.Contains(d.NormalizedKey) && d.BaseWeight > 1.0)
            .OrderByDescending(d => d.BaseWeight).FirstOrDefault();

        if (idField != null && locField != null)
        {
            double synergy = BetaDirectIdentity * Math.Sqrt(idField.BaseWeight * locField.BaseWeight);
            clusters.Add(new RiskClusterMatch
            {
                ClusterId = "K_identity",
                Name = "Direct Deanonymization Cluster",
                Beta = BetaDirectIdentity,
                SynergyContribution = Math.Round(synergy, 2),
                InvolvedTags = [idField.NormalizedKey, locField.NormalizedKey]
            });
        }

        double clusterSum = clusters.Sum(c => c.SynergyContribution);
        double pri = Math.Round(Math.Min(100.0, linearSum + clusterSum), 1);
        string band = pri >= 50.0
            ? "Critical Risk"
            : pri >= 20.0
                ? "Moderate Risk"
                : "Low Risk";

        return (pri, band, clusters);
    }

    public static double CalculatePer(double priIn, double priClean)
    {
        if (priIn <= 0.0) return 0.0;
        var per = ((priIn - priClean) / priIn) * 100.0;
        return Math.Round(Math.Clamp(per, 0.0, 100.0), 1);
    }

    public static UsabilityPreservationMetrics EvaluateUsability(
        string fileName,
        MetaCoreReport before,
        MetaCoreReport after)
    {
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        var beforeKeys = before.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var afterKeys = after.Details.Select(d => d.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool hadIcc = beforeKeys.Any(IsIccKey);
        bool keptIcc = !hadIcc || afterKeys.Any(IsIccKey);

        bool hadOrient = beforeKeys.Contains("Orientation") || beforeKeys.Contains("Rotate");
        bool keptOrient = !hadOrient || afterKeys.Contains("Orientation") || afterKeys.Contains("Rotate");

        bool isPdf = ext == ".pdf";
        bool hadPdfTree = HasBoolTrue(before, "HasStructTreeRoot");
        bool keptPdfTree = !isPdf || !hadPdfTree || HasBoolTrue(after, "HasStructTreeRoot");

        bool isOpenXml = ext is ".docx" or ".pptx" or ".xlsx";
        bool openXmlOk = !isOpenXml || !HasBoolFalse(after, "OpenXMLIntegrity");

        bool keptDims = (!beforeKeys.Contains("ImageWidth") || afterKeys.Contains("ImageWidth")) &&
                        (!beforeKeys.Contains("ImageHeight") || afterKeys.Contains("ImageHeight"));

        int totalChecks = 0;
        int passedChecks = 0;

        totalChecks++; if (keptDims) passedChecks++;
        if (hadIcc) { totalChecks++; if (keptIcc) passedChecks++; }
        if (hadOrient) { totalChecks++; if (keptOrient) passedChecks++; }
        if (isPdf && hadPdfTree) { totalChecks++; if (keptPdfTree) passedChecks++; }
        if (isOpenXml) { totalChecks++; if (openXmlOk) passedChecks++; }

        double score = totalChecks == 0 ? 100.0 : Math.Round((double)passedChecks / totalChecks * 100.0, 1);

        return new UsabilityPreservationMetrics
        {
            HadColorProfile = hadIcc,
            ColorProfilePreserved = keptIcc,
            HadOrientation = hadOrient,
            OrientationPreserved = keptOrient,
            IsPdf = isPdf,
            HadPdfAccessibilityTree = hadPdfTree,
            PdfAccessibilityPreserved = keptPdfTree,
            IsOpenXml = isOpenXml,
            OpenXmlIntegrityPreserved = openXmlOk,
            CompositeUsabilityScore = score
        };
    }

    private static bool IsIccKey(string k) =>
        k.Contains("ICC", StringComparison.OrdinalIgnoreCase) ||
        k.StartsWith("Profile", StringComparison.OrdinalIgnoreCase) ||
        k.Equals("ColorSpace", StringComparison.OrdinalIgnoreCase) ||
        k.Equals("SRGBRendering", StringComparison.OrdinalIgnoreCase);

    private static bool HasBoolTrue(MetaCoreReport report, string key) =>
        report.Details.Any(d =>
            d.NormalizedKey.Equals(key, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(d.Value?.ToString(), "true", StringComparison.OrdinalIgnoreCase));

    private static bool HasBoolFalse(MetaCoreReport report, string key) =>
        report.Details.Any(d =>
            d.NormalizedKey.Equals(key, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(d.Value?.ToString(), "false", StringComparison.OrdinalIgnoreCase));
}
