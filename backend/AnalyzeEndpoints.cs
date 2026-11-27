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
                TamperAuditReport? tamperAudit = null;
                string? engine = null;
                try
                {
                    var extracted = await extractor.ExtractAsync(tempPath, safeName);
                    metadata = extracted.Metadata;
                    engine = extracted.Engine;
                    tamperAudit = TamperDetectionService.Audit(metadata);
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
                    metaCore = report,
                    tamperAudit
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
                response.Headers["X-MetaGuard-PRI-Before"] = result.BeforeReport.PrivacyRiskIndex.ToString("F1");
                response.Headers["X-MetaGuard-PRI-After"] = result.AfterReport.PrivacyRiskIndex.ToString("F1");
                response.Headers["X-MetaGuard-PER"] = result.PrivacyExposureReductionPercent.ToString("F1");
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

        // Just-In-Time Volatile OS Mediation Endpoint (Web Share Target / Local Client Hand-off)
        app.MapPost("/api/mediate", async (
            HttpRequest request,
            AppDbContext db,
            ClaimsPrincipal user,
            OsMediationService mediator,
            SanitizedFileStore fileStore) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Expected multipart form-data" });

            var form = await request.ReadFormAsync();
            var files = form.Files.Where(f => f.Name is "files" or "file" or "media").ToList();
            if (files.Count == 0) return Results.BadRequest(new { error = "No shared files received" });

            var options = ParseSanitizeOptions(form, defaultTier3Normalize: true);
            var sourceChannel = string.IsNullOrWhiteSpace(form["sourceChannel"]) ? "web-share-target" : form["sourceChannel"].ToString();

            var inputs = new List<OsMediationInput>(files.Count);
            foreach (var file in files)
            {
                await using var mem = new MemoryStream();
                await file.CopyToAsync(mem);
                inputs.Add(new OsMediationInput
                {
                    FileName = Path.GetFileName(file.FileName),
                    ContentType = file.ContentType ?? "application/octet-stream",
                    Payload = mem.ToArray(),
                    SourceChannel = sourceChannel
                });
            }

            var (batch, items) = await mediator.MediateBatchAsync(inputs, options, sourceChannel, request.HttpContext.RequestAborted);
            foreach (var (assetResult, cleanBytes) in items)
            {
                var dispatchId = fileStore.Save(assetResult.SanitizedFileName, assetResult.ContentType, cleanBytes);
                assetResult.DispatchId = dispatchId;
                assetResult.DispatchUri = $"/api/sanitize/download/{dispatchId}";
            }

            if (batch.Assets.Count == 0)
                return Results.BadRequest(new { error = string.Join("; ", batch.Errors), batch });

            await TrySaveScanAsync(db, user, "mediate", files.Count == 1 ? Path.GetFileName(files[0].FileName) : $"{files.Count} mediated assets", batch);
            return Results.Ok(batch);
        });

        app.MapPost("/api/mediate/file", async (
            HttpRequest request,
            HttpResponse response,
            OsMediationService mediator) =>
        {
            if (!request.HasFormContentType) return Results.BadRequest(new { error = "Expected multipart form-data" });

            var form = await request.ReadFormAsync();
            var file = form.Files.FirstOrDefault(f => f.Name is "file" or "files" or "media");
            if (file == null) return Results.BadRequest(new { error = "No shared file received" });

            var options = ParseSanitizeOptions(form, defaultTier3Normalize: true);
            await using var mem = new MemoryStream();
            await file.CopyToAsync(mem);

            try
            {
                var (result, sanitizedBytes) = await mediator.MediateAssetAsync(new OsMediationInput
                {
                    FileName = Path.GetFileName(file.FileName),
                    ContentType = file.ContentType ?? "application/octet-stream",
                    Payload = mem.ToArray(),
                    SourceChannel = string.IsNullOrWhiteSpace(form["sourceChannel"]) ? "os-mediation-api" : form["sourceChannel"].ToString()
                }, options, request.HttpContext.RequestAborted);

                response.Headers["X-MetaGuard-ZeroTransit"] = result.ZeroTransitVerified.ToString();
                response.Headers["X-MetaGuard-VolatileMemory"] = result.VolatileMemoryOnly.ToString();
                response.Headers["X-MetaGuard-PRI-Before"] = result.BeforePri.ToString("F1");
                response.Headers["X-MetaGuard-PRI-After"] = result.AfterPri.ToString("F1");
                response.Headers["X-MetaGuard-PER"] = result.PrivacyExposureReductionPercent.ToString("F1");
                response.Headers["X-MetaGuard-Tampered"] = result.TamperAudit.IsTampered.ToString();
                response.Headers["X-MetaGuard-Usability"] = result.Usability.CompositeUsabilityScore.ToString("F1");
                response.Headers["X-MetaGuard-Latency-Ms"] = result.ProcessingLatencyMs.ToString("F2");
                response.Headers["X-MetaCore-Engine"] = result.EngineUsed;
                response.Headers["X-MetaCore-Removed-Count"] = result.RemovedFields.Count.ToString();
                response.Headers["X-MetaCore-Kept-Count"] = result.KeptFields.Count.ToString();
                return Results.File(sanitizedBytes, result.ContentType, result.SanitizedFileName);
            }
            catch (Exception ex)
            {
                return Results.BadRequest(new { error = ex.Message });
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

    private static MetaSanitizeOptions ParseSanitizeOptions(IFormCollection form, bool defaultTier3Normalize = false)
    {
        var options = new MetaSanitizeOptions
        {
            EnableTier3Normalization = defaultTier3Normalize
        };

        if (bool.TryParse(form["keepRequired"], out var keepReq))
            options.KeepRequired = keepReq;
        if (bool.TryParse(form["keepLowPriority"], out var keepLow))
            options.KeepLowPriority = keepLow;
        if (bool.TryParse(form["strictMode"], out var strict))
            options.StrictMode = strict;
        if (bool.TryParse(form["enableTier3Normalization"], out var tier3))
            options.EnableTier3Normalization = tier3;

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
