using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Pure-C# volatile in-memory PDF metadata extractor and ISO 32000-1 incremental-update sanitizer
/// that strips/normalizes /Info and XMP /Metadata while strictly preserving /StructTreeRoot (PDF/UA)
/// accessibility trees, page objects, and content streams.
/// </summary>
public static class NativePdfHandler
{
    public static void ExtractMetadata(byte[] bytes, JsonObject meta)
    {
        meta["FileType"] = "PDF";
        meta["FileTypeExtension"] = "pdf";
        meta["MIMEType"] = "application/pdf";

        var text = Encoding.Latin1.GetString(bytes);
        var verMatch = Regex.Match(text, @"%PDF-(\d+\.\d+)");
        if (verMatch.Success)
            meta["PDFVersion"] = verMatch.Groups[1].Value;

        var objects = IndexIndirectObjects(text);
        int pageCount = Regex.Matches(text, @"/Type\s*/Page(?![sA-Za-z])").Count;
        if (pageCount > 0) meta["PageCount"] = pageCount;

        // Inspect /Catalog (from last /Root reference in trailers)
        var rootRefs = Regex.Matches(text, @"/Root\s+(\d+)\s+\d+\s+R");
        if (rootRefs.Count > 0 && int.TryParse(rootRefs[^1].Groups[1].Value, out int rootId) &&
            objects.TryGetValue(rootId, out var rootBody))
        {
            bool hasStructTree = Regex.IsMatch(rootBody, @"/StructTreeRoot\b");
            bool hasMarkedInfo = Regex.IsMatch(rootBody, @"/MarkInfo\b");
            meta["HasStructTreeRoot"] = hasStructTree;
            meta["MarkInfo"] = hasMarkedInfo;
            meta["PDFUACompliant"] = hasStructTree && hasMarkedInfo;

            var xmpRefMatch = Regex.Match(rootBody, @"/Metadata\s+(\d+)\s+\d+\s+R");
            if (xmpRefMatch.Success && int.TryParse(xmpRefMatch.Groups[1].Value, out int xmpId) &&
                objects.TryGetValue(xmpId, out var xmpObjBody))
            {
                var xmpXml = ExtractStreamText(xmpObjBody);
                if (!string.IsNullOrWhiteSpace(xmpXml))
                    ExtractXmpTags(xmpXml, meta);
            }
        }
        else
        {
            meta["HasStructTreeRoot"] = Regex.IsMatch(text, @"/StructTreeRoot\b");
            meta["MarkInfo"] = Regex.IsMatch(text, @"/MarkInfo\b");
            meta["PDFUACompliant"] = Regex.IsMatch(text, @"/StructTreeRoot\b");
        }

        // Inspect last trailer /Info dictionary
        var infoRefs = Regex.Matches(text, @"/Info\s+(\d+)\s+\d+\s+R");
        if (infoRefs.Count > 0 && int.TryParse(infoRefs[^1].Groups[1].Value, out int infoId) &&
            objects.TryGetValue(infoId, out var infoBody))
        {
            ParsePdfDictionaryStrings(infoBody, meta);
        }
    }

    public static byte[] SanitizeBytes(
        byte[] bytes,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        var text = Encoding.Latin1.GetString(bytes);
        var objects = IndexIndirectObjects(text);

        var startXrefMatches = Regex.Matches(text, @"startxref\s+(\d+)");
        long prevXref = startXrefMatches.Count > 0 && long.TryParse(startXrefMatches[^1].Groups[1].Value, out var px)
            ? px
            : 0;

        var rootRefs = Regex.Matches(text, @"/Root\s+(\d+)\s+(\d+)\s+R");
        if (rootRefs.Count == 0)
            return bytes;

        string rootRefStr = $"{rootRefs[^1].Groups[1].Value} {rootRefs[^1].Groups[2].Value} R";
        int rootId = int.Parse(rootRefs[^1].Groups[1].Value, CultureInfo.InvariantCulture);
        int maxObjId = objects.Count > 0 ? objects.Keys.Max() : rootId;

        var infoRefs = Regex.Matches(text, @"/Info\s+(\d+)\s+(\d+)\s+R");
        int infoObjId = infoRefs.Count > 0
            ? int.Parse(infoRefs[^1].Groups[1].Value, CultureInfo.InvariantCulture)
            : ++maxObjId;

        var newInfoDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (objects.TryGetValue(infoObjId, out var oldInfoBody))
        {
            var tempMeta = new JsonObject();
            ParsePdfDictionaryStrings(oldInfoBody, tempMeta);
            foreach (var kvp in tempMeta)
            {
                var raw = kvp.Value?.ToString();
                if (string.IsNullOrEmpty(raw)) continue;
                if (actions.TryGetValue(kvp.Key, out var act))
                {
                    if (act == MetaAction.Keep)
                        newInfoDict[kvp.Key] = raw;
                    else if (act == MetaAction.Normalize && normalizedValues != null && normalizedValues.TryGetValue(kvp.Key, out var norm))
                        newInfoDict[kvp.Key] = norm;
                }
            }
        }

        // Check whether an XMP /Metadata object exists on /Root to override cleanly
        int? xmpObjId = null;
        string? newXmpPacket = null;
        if (objects.TryGetValue(rootId, out var rootBody))
        {
            var m = Regex.Match(rootBody, @"/Metadata\s+(\d+)\s+\d+\s+R");
            if (m.Success && int.TryParse(m.Groups[1].Value, out int parsedXmpId) &&
                objects.TryGetValue(parsedXmpId, out var xmpObjBody))
            {
                var existingXmp = ExtractStreamText(xmpObjBody);
                if (!string.IsNullOrWhiteSpace(existingXmp))
                {
                    xmpObjId = parsedXmpId;
                    newXmpPacket = SanitizeXmpXml(existingXmp, actions, normalizedValues);
                }
            }
        }

        // Build clean ISO 32000-1 incremental update without touching existing offsets (/StructTreeRoot & pages preserved byte-for-byte)
        using var ms = new MemoryStream(bytes.Length + 2048);
        ms.Write(bytes, 0, bytes.Length);
        if (bytes.Length == 0 || (bytes[^1] != (byte)'\n' && bytes[^1] != (byte)'\r'))
            WriteAscii(ms, "\n");

        var updatedOffsets = new SortedDictionary<int, long>();

        // 1. Write sanitized /Info indirect object
        updatedOffsets[infoObjId] = ms.Position;
        var infoSb = new StringBuilder();
        infoSb.Append($"{infoObjId} 0 obj\n<<");
        foreach (var kvp in newInfoDict)
        {
            infoSb.Append($" /{kvp.Key} ({EscapePdfLiteral(kvp.Value)})");
        }
        infoSb.Append(" >>\nendobj\n");
        WriteAscii(ms, infoSb.ToString());

        // 2. Override XMP /Metadata stream object if present
        if (xmpObjId.HasValue && newXmpPacket != null)
        {
            updatedOffsets[xmpObjId.Value] = ms.Position;
            var xmpBytes = new UTF8Encoding(false).GetBytes(newXmpPacket);
            WriteAscii(ms, $"{xmpObjId.Value} 0 obj\n<< /Type /Metadata /Subtype /XML /Length {xmpBytes.Length} >>\nstream\n");
            ms.Write(xmpBytes, 0, xmpBytes.Length);
            WriteAscii(ms, "\nendstream\nendobj\n");
        }

        // 3. Write incremental cross-reference table
        long newXrefOffset = ms.Position;
        WriteAscii(ms, "xref\n");
        foreach (var kvp in updatedOffsets)
        {
            WriteAscii(ms, $"{kvp.Key} 1\n");
            WriteAscii(ms, $"{kvp.Value:D10} 00000 n \n");
        }

        int finalSize = Math.Max(maxObjId, updatedOffsets.Keys.Max()) + 1;
        WriteAscii(ms, $"trailer\n<< /Size {finalSize} /Root {rootRefStr} /Info {infoObjId} 0 R /Prev {prevXref} >>\nstartxref\n{newXrefOffset}\n%%EOF\n");

        return ms.ToArray();
    }

    private static Dictionary<int, string> IndexIndirectObjects(string text)
    {
        var dict = new Dictionary<int, string>();
        var matches = Regex.Matches(text, @"(?:^|\r|\n)(\d+)\s+\d+\s+obj\b(.*?)endobj", RegexOptions.Singleline);
        foreach (Match m in matches)
        {
            if (int.TryParse(m.Groups[1].Value, out int objId))
                dict[objId] = m.Groups[2].Value; // Later incremental definitions automatically override earlier ones
        }
        return dict;
    }

    private static void ParsePdfDictionaryStrings(string dictBody, JsonObject meta)
    {
        // Match /Key (literal) entries outside nested brackets cleanly
        foreach (Match m in Regex.Matches(dictBody, @"/([A-Za-z0-9_]+)\s*\(((?:\\.|[^\\)])*)\)"))
        {
            var key = m.Groups[1].Value;
            var val = UnescapePdfLiteral(m.Groups[2].Value);
            if (!string.IsNullOrWhiteSpace(val))
                meta[key] = val;
        }
    }

    private static string? ExtractStreamText(string objBody)
    {
        var m = Regex.Match(objBody, @"stream\r?\n(.*?)\r?\n?endstream", RegexOptions.Singleline);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static void ExtractXmpTags(string xml, JsonObject meta)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            foreach (var desc in doc.Descendants().Where(e => e.Name.LocalName == "Description"))
            {
                foreach (var el in desc.Elements())
                {
                    var prefix = desc.GetPrefixOfNamespace(el.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{el.Name.LocalName}" : $"XMP-{prefix}:{el.Name.LocalName}";
                    var val = el.Value.Trim();
                    if (!string.IsNullOrEmpty(val)) meta[key] = val;
                }
            }
        }
        catch { }
    }

    private static string SanitizeXmpXml(
        string xml,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            foreach (var desc in doc.Descendants().Where(e => e.Name.LocalName == "Description").ToList())
            {
                foreach (var el in desc.Elements().ToList())
                {
                    var prefix = desc.GetPrefixOfNamespace(el.Name.Namespace);
                    var key = string.IsNullOrEmpty(prefix) ? $"XMP:{el.Name.LocalName}" : $"XMP-{prefix}:{el.Name.LocalName}";
                    var normKey = el.Name.LocalName;

                    if (actions.TryGetValue(key, out var act) || actions.TryGetValue(normKey, out act))
                    {
                        if (act == MetaAction.Remove)
                            el.Remove();
                        else if (act == MetaAction.Normalize && normalizedValues != null &&
                                 (normalizedValues.TryGetValue(key, out var nv) || normalizedValues.TryGetValue(normKey, out nv)))
                            el.Value = nv;
                    }
                    else
                    {
                        el.Remove();
                    }
                }
            }

            return doc.ToString(SaveOptions.DisableFormatting);
        }
        catch
        {
            return "<?xpacket begin=\"\ufeff\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>" +
                   "<?xpacket end=\"w\"?>";
        }
    }

    private static string EscapePdfLiteral(string s) =>
        s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");

    private static string UnescapePdfLiteral(string s) =>
        s.Replace("\\(", "(").Replace("\\)", ")").Replace("\\\\", "\\");

    private static void WriteAscii(Stream ms, string s)
    {
        var b = Encoding.Latin1.GetBytes(s);
        ms.Write(b, 0, b.Length);
    }
}
