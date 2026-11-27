using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Security.Claims;
using MetaDetective.Api.Data;
using MetaDetective.Api.MetaCore;
using System.Text.Json.Nodes;

public static class AnalyzeEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/analyze", async (
            HttpRequest request,
            AppDbContext db,
            ClaimsPrincipal user,
            MetadataExtractorService extractor,
            MetaCoreEngine metaCore) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Expected form-data" });

            var form = await request.ReadFormAsync();
            var files = form.Files.Where(f => f.Name == "files" || f.Name == "file").ToList();
            if (files.Count == 0) return Results.BadRequest(new { error = "No file uploaded" });

            var options = ParseSanitizeOptions(form);
            var results = new List<object>();

            foreach (var file in files)
            {
                var safeName = Path.GetFileName(file.FileName);
                var tempPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}_{safeName}");

                await using (var stream = new FileStream(tempPath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                JsonObject? metadata = null;
                MetaCoreReport? report = null;
                string? engine = null;
                try
                {
                    var extracted = await extractor.ExtractAsync(tempPath, safeName);
                    metadata = extracted.Metadata;
                    engine = extracted.Engine;
                    report = metaCore.AnalyzeMetadata(metadata, options);
                }
                catch (Exception ex)
                {
                    metadata = new JsonObject { ["Error"] = ex.Message };
                }
                finally
                {
                    if (File.Exists(tempPath)) File.Delete(tempPath);
                }

                results.Add(new
                {
                    filename = safeName,
                    engine,
                    metadata,
                    metaCore = report
                });
            }

            await TrySaveScanAsync(db, user, "file", files.Count == 1 ? Path.GetFileName(files[0].FileName) : $"{files.Count} files", results);
            return Results.Ok(results);
        });

        app.MapPost("/api/sanitize", async (
            HttpRequest request,
            AppDbContext db,
            ClaimsPrincipal user,
            FileSanitizerService sanitizer,
            SanitizedFileStore fileStore) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Expected form-data" });

            var form = await request.ReadFormAsync();
            var files = form.Files.Where(f => f.Name == "files" || f.Name == "file").ToList();
            if (files.Count == 0) return Results.BadRequest(new { error = "No file uploaded" });

            var options = ParseSanitizeOptions(form);
            var results = new List<object>();
            var errors = new List<string>();

            foreach (var file in files)
            {
                var safeName = Path.GetFileName(file.FileName);
                var tempPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}_{safeName}");

                await using (var stream = new FileStream(tempPath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                try
                {
                    var (result, sanitizedBytes) = await sanitizer.SanitizeFileAsync(tempPath, safeName, file.ContentType, options);
                    var downloadId = fileStore.Save(result.SanitizedFileName, result.ContentType, sanitizedBytes);
                    result.DownloadId = downloadId;
                    result.DownloadUrl = $"/api/sanitize/download/{downloadId}";
                    results.Add(result);
                }
                catch (Exception ex)
                {
                    errors.Add($"{safeName}: {ex.Message}");
                    results.Add(new { fileName = safeName, error = ex.Message });
                }
                finally
                {
                    if (File.Exists(tempPath)) File.Delete(tempPath);
                }
            }

            if (errors.Count == files.Count)
                return Results.BadRequest(new { error = string.Join("; ", errors), results });

            await TrySaveScanAsync(db, user, "sanitize", files.Count == 1 ? Path.GetFileName(files[0].FileName) : $"{files.Count} files", results);
            return Results.Ok(results);
        });

        app.MapGet("/api/sanitize/download/{id}", (string id, SanitizedFileStore fileStore) =>
        {
            if (!fileStore.TryGet(id, out var stored) || stored == null)
                return Results.NotFound(new { error = "Sanitized file not found or expired." });

            return Results.File(stored.Content, stored.ContentType, stored.FileName);
        });

        app.MapPost("/api/sanitize/file", async (
            HttpRequest request,
            HttpResponse response,
            FileSanitizerService sanitizer) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Expected form-data" });

            var form = await request.ReadFormAsync();
            var file = form.Files.FirstOrDefault(f => f.Name == "file" || f.Name == "files");
            if (file == null) return Results.BadRequest(new { error = "No file uploaded" });

            var options = ParseSanitizeOptions(form);
            var safeName = Path.GetFileName(file.FileName);
            var tempPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}_{safeName}");

            await using (var stream = new FileStream(tempPath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            try
            {
                var (result, sanitizedBytes) = await sanitizer.SanitizeFileAsync(tempPath, safeName, file.ContentType, options);
                response.Headers["X-MetaCore-Engine"] = result.EngineUsed;
                response.Headers["X-MetaCore-Removed-Count"] = result.RemovedFields.Count.ToString();
                response.Headers["X-MetaCore-Kept-Count"] = result.KeptFields.Count.ToString();
                response.Headers["X-MetaCore-Risk-Before"] = result.BeforeReport.RiskLevel;
                response.Headers["X-MetaCore-Risk-After"] = result.AfterReport.RiskLevel;
                return Results.File(sanitizedBytes, result.ContentType, result.SanitizedFileName);
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
            finally
            {
                if (File.Exists(tempPath)) File.Delete(tempPath);
            }
        });

        app.MapPost("/api/scrape", async ([FromBody] ScrapeRequest req, AppDbContext db, ClaimsPrincipal user) =>
        {
            var results = new List<object>();
            JsonNode? metadata = null;
            try
            {
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("User-Agent", "MetaDetective/1.0");
                var html = await client.GetStringAsync(req.Url);
                var doc = new HtmlAgilityPack.HtmlDocument();
                doc.LoadHtml(html);
                var title = doc.DocumentNode.SelectSingleNode("//title")?.InnerText ?? "No Title";

                metadata = new JsonObject
                {
                    ["url"] = req.Url,
                    ["title"] = title
                };
            }
            catch (Exception ex)
            {
                metadata = new JsonObject { ["error"] = ex.Message };
            }

            results.Add(new
            {
                filename = req.Url,
                metadata
            });

            await TrySaveScanAsync(db, user, "url", req.Url, results);
            return Results.Ok(results);
        });

        app.MapPost("/api/geocode", async ([FromBody] GeocodeRequest req) =>
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Add("User-Agent", "MetaDetective/1.0");
            var url = $"https://nominatim.openstreetmap.org/reverse?format=json&lat={req.Lat}&lon={req.Lon}";

            try
            {
                var response = await client.GetStringAsync(url);
                return Results.Ok(JsonDocument.Parse(response));
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
            }
        });
    }

    private static MetaSanitizeOptions ParseSanitizeOptions(IFormCollection form)
    {
        var options = new MetaSanitizeOptions();

        if (bool.TryParse(form["keepRequired"], out var keepReq))
            options.KeepRequired = keepReq;
        if (bool.TryParse(form["keepLowPriority"], out var keepLow))
            options.KeepLowPriority = keepLow;
        if (bool.TryParse(form["strictMode"], out var strict))
            options.StrictMode = strict;

        options.KeepTags = ParseTagList(form["keepTags"]);
        options.RemoveTags = ParseTagList(form["removeTags"]);
        return options;
    }

    private static List<string> ParseTagList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new List<string>();
        var trimmed = raw.Trim();
        if (trimmed.StartsWith('['))
        {
            try
            {
                return JsonSerializer.Deserialize<List<string>>(trimmed) ?? new List<string>();
            }
            catch { }
        }
        return trimmed.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    private static async Task TrySaveScanAsync(AppDbContext db, ClaimsPrincipal user, string scanType, string name, object results)
    {
        var userIdStr = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdStr, out var userId)) return;

        try
        {
            var scan = new Scan
            {
                UserId = userId,
                ScanType = scanType,
                Name = name,
                Result = JsonSerializer.SerializeToDocument(results)
            };
            db.Scans.Add(scan);
            await db.SaveChangesAsync();
        }
        catch
        {
            // Do not fail metadata extraction/sanitization if optional scan persistence fails.
        }
    }
}

public class ScrapeRequest
{
    public string Url { get; set; } = string.Empty;
}

public class GeocodeRequest
{
    public double Lat { get; set; }
    public double Lon { get; set; }
}
