using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace MetaDetective.Api.MetaCore;

/// <summary>
/// Pure-C# volatile in-memory reader and selective sanitizer for Office OpenXML containers
/// (.docx, .pptx, .xlsx), preserving package relationships, content types, and document layouts.
/// </summary>
public static class NativeOpenXmlHandler
{
    public static void ExtractMetadata(byte[] bytes, JsonObject meta, string ext)
    {
        meta["FileType"] = ext.TrimStart('.').ToUpperInvariant();
        meta["FileTypeExtension"] = ext.TrimStart('.');
        meta["MIMEType"] = ext switch
        {
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _ => "application/octet-stream"
        };

        using var ms = new MemoryStream(bytes, writable: false);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        bool hasContentTypes = zip.GetEntry("[Content_Types].xml") != null;
        bool hasRootRels = zip.GetEntry("_rels/.rels") != null;
        meta["OpenXMLIntegrity"] = hasContentTypes && hasRootRels;
        meta["OpenXMLRelationships"] = zip.Entries.Count(e => e.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase));

        ReadXmlProperties(zip.GetEntry("docProps/core.xml"), meta, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["creator"] = "Author",
            ["lastModifiedBy"] = "LastModifiedBy",
            ["created"] = "CreateDate",
            ["modified"] = "ModifyDate",
            ["title"] = "Title",
            ["subject"] = "Subject",
            ["description"] = "Description",
            ["keywords"] = "Keywords",
            ["revision"] = "Revision"
        });

        ReadXmlProperties(zip.GetEntry("docProps/app.xml"), meta, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Application"] = "Application",
            ["AppVersion"] = "AppVersion",
            ["Company"] = "Company",
            ["Manager"] = "Manager",
            ["Template"] = "Template",
            ["TotalTime"] = "TotalTime",
            ["Pages"] = "PageCount",
            ["Slides"] = "PageCount"
        });

        var customEntry = zip.GetEntry("docProps/custom.xml");
        if (customEntry != null)
        {
            try
            {
                using var s = customEntry.Open();
                var doc = XDocument.Load(s);
                foreach (var prop in doc.Root?.Elements() ?? Enumerable.Empty<XElement>())
                {
                    var name = prop.Attribute("name")?.Value;
                    if (!string.IsNullOrWhiteSpace(name))
                        meta[$"Custom:{name}"] = prop.Value;
                }
            }
            catch { }
        }

        int commentParts = zip.Entries.Count(e =>
            e.FullName.Contains("comments", StringComparison.OrdinalIgnoreCase) &&
            e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
        if (commentParts > 0)
            meta["Comments"] = $"{commentParts} embedded comment part(s)";

        var docXmlEntry = zip.GetEntry("word/document.xml");
        if (docXmlEntry != null)
        {
            try
            {
                using var s = docXmlEntry.Open();
                var doc = XDocument.Load(s);
                var trackedAuthors = doc.Descendants()
                    .SelectMany(e => e.Attributes())
                    .Where(a => a.Name.LocalName == "author" && !string.IsNullOrWhiteSpace(a.Value))
                    .Select(a => a.Value)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (trackedAuthors.Count > 0)
                    meta["Creator"] = string.Join(", ", trackedAuthors);
            }
            catch { }
        }
    }

    public static byte[] SanitizeBytes(
        byte[] bytes,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        using var inMs = new MemoryStream(bytes, writable: false);
        using var inZip = new ZipArchive(inMs, ZipArchiveMode.Read);
        using var outMs = new MemoryStream();
        using (var outZip = new ZipArchive(outMs, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var entry in inZip.Entries)
            {
                // Drop custom metadata & editorial comment XML parts completely unless explicitly kept
                if (entry.FullName.Equals("docProps/custom.xml", StringComparison.OrdinalIgnoreCase) &&
                    !ShouldKeep(actions, "Comments"))
                {
                    continue;
                }

                if (entry.FullName.Contains("comments", StringComparison.OrdinalIgnoreCase) &&
                    entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) &&
                    !ShouldKeep(actions, "Comments"))
                {
                    continue;
                }

                byte[] entryBytes;
                using (var es = entry.Open())
                using (var tmp = new MemoryStream())
                {
                    es.CopyTo(tmp);
                    entryBytes = tmp.ToArray();
                }

                if (entry.FullName.Equals("docProps/core.xml", StringComparison.OrdinalIgnoreCase))
                {
                    entryBytes = SanitizeXmlPropertyPart(entryBytes, actions, normalizedValues, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["creator"] = "Author",
                        ["lastModifiedBy"] = "LastModifiedBy",
                        ["created"] = "CreateDate",
                        ["modified"] = "ModifyDate",
                        ["title"] = "Title",
                        ["subject"] = "Subject",
                        ["description"] = "Description",
                        ["keywords"] = "Keywords",
                        ["revision"] = "Revision"
                    });
                }
                else if (entry.FullName.Equals("docProps/app.xml", StringComparison.OrdinalIgnoreCase))
                {
                    entryBytes = SanitizeXmlPropertyPart(entryBytes, actions, normalizedValues, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Application"] = "Application",
                        ["AppVersion"] = "AppVersion",
                        ["Company"] = "Company",
                        ["Manager"] = "Manager",
                        ["Template"] = "Template",
                        ["TotalTime"] = "TotalTime",
                        ["Pages"] = "PageCount",
                        ["Slides"] = "PageCount"
                    });
                }
                else if (entry.FullName.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase))
                {
                    entryBytes = SanitizeRevisionAttributes(entryBytes, actions, normalizedValues);
                }

                var newEntry = outZip.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                using var dest = newEntry.Open();
                dest.Write(entryBytes, 0, entryBytes.Length);
            }
        }

        return outMs.ToArray();
    }

    private static void ReadXmlProperties(ZipArchiveEntry? entry, JsonObject meta, Dictionary<string, string> map)
    {
        if (entry == null) return;
        try
        {
            using var s = entry.Open();
            var doc = XDocument.Load(s);
            if (doc.Root == null) return;
            foreach (var el in doc.Root.Elements())
            {
                if (map.TryGetValue(el.Name.LocalName, out var metaKey) && !string.IsNullOrWhiteSpace(el.Value))
                    meta[metaKey] = el.Value.Trim();
            }
        }
        catch { }
    }

    private static byte[] SanitizeXmlPropertyPart(
        byte[] xmlBytes,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues,
        Dictionary<string, string> map)
    {
        try
        {
            using var ms = new MemoryStream(xmlBytes);
            var doc = XDocument.Load(ms);
            if (doc.Root == null) return xmlBytes;

            foreach (var el in doc.Root.Elements().ToList())
            {
                if (!map.TryGetValue(el.Name.LocalName, out var metaKey))
                    continue;

                if (actions.TryGetValue(metaKey, out var act))
                {
                    if (act == MetaAction.Remove)
                    {
                        el.Remove();
                    }
                    else if (act == MetaAction.Normalize &&
                             normalizedValues != null &&
                             normalizedValues.TryGetValue(metaKey, out var norm))
                    {
                        el.Value = norm;
                    }
                }
                else if (!metaKey.Equals("PageCount", StringComparison.OrdinalIgnoreCase))
                {
                    el.Remove();
                }
            }

            return new UTF8Encoding(false).GetBytes(doc.ToString(SaveOptions.DisableFormatting));
        }
        catch
        {
            return xmlBytes;
        }
    }

    private static byte[] SanitizeRevisionAttributes(
        byte[] xmlBytes,
        Dictionary<string, MetaAction> actions,
        Dictionary<string, string>? normalizedValues)
    {
        try
        {
            using var ms = new MemoryStream(xmlBytes);
            var doc = XDocument.Load(ms);
            bool modified = false;

            if (!ShouldKeep(actions, "Creator") && !ShouldKeep(actions, "Author"))
            {
                foreach (var attr in doc.Descendants().SelectMany(e => e.Attributes()).Where(a => a.Name.LocalName == "author").ToList())
                {
                    attr.Value = "Redacted";
                    modified = true;
                }
            }

            if (actions.TryGetValue("ModifyDate", out var modAct) && modAct != MetaAction.Keep)
            {
                foreach (var attr in doc.Descendants().SelectMany(e => e.Attributes()).Where(a => a.Name.LocalName == "date").ToList())
                {
                    if (modAct == MetaAction.Normalize && normalizedValues != null && normalizedValues.TryGetValue("ModifyDate", out var norm))
                        attr.Value = norm;
                    else
                        attr.Remove();
                    modified = true;
                }
            }

            return modified ? new UTF8Encoding(false).GetBytes(doc.ToString(SaveOptions.DisableFormatting)) : xmlBytes;
        }
        catch
        {
            return xmlBytes;
        }
    }

    private static bool ShouldKeep(Dictionary<string, MetaAction> actions, string key) =>
        actions.TryGetValue(key, out var act) && act == MetaAction.Keep;
}
