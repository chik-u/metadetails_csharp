using System.Collections.Concurrent;
using Android.Content;
using Android.Database;
using Android.OS;
using Android.Provider;

namespace MetaGuard.Android;

/// <summary>
/// Volatile RAM-backed Android ContentProvider serving sanitized media buffers
/// over ParcelFileDescriptor.CreatePipe() so cleaned artifacts bypass flash storage
/// until consumed by the downstream share recipient.
/// </summary>
[ContentProvider(
    new[] { Authority },
    Name = "com.metaguard.mediator.MetaGuardContentProvider",
    Exported = false,
    GrantUriPermissions = true)]
public sealed class MetaGuardContentProvider : ContentProvider
{
    public const string Authority = "com.metaguard.mediator.provider";

    public sealed record EphemeralAsset(
        byte[] Data,
        string FileName,
        string ContentType,
        DateTime ExpiresUtc);

    private static readonly ConcurrentDictionary<string, EphemeralAsset> VolatileStore = new();

    public static global::Android.Net.Uri StoreInMemory(byte[] sanitizedBytes, string fileName, string contentType)
    {
        PruneExpired();
        var token = Guid.NewGuid().ToString("N");
        var safeName = Path.GetFileName(fileName);
        VolatileStore[token] = new EphemeralAsset(
            sanitizedBytes,
            safeName,
            string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
            DateTime.UtcNow.AddMinutes(10));

        return new global::Android.Net.Uri.Builder()
            .Scheme("content")!
            .Authority(Authority)!
            .AppendPath(token)!
            .AppendPath(safeName)!
            .Build()!;
    }

    public override bool OnCreate() => true;

    public override string? GetType(global::Android.Net.Uri uri) =>
        TryResolve(uri, out var asset) ? asset!.ContentType : null;

    public override ICursor? Query(
        global::Android.Net.Uri uri,
        string[]? projection,
        string? selection,
        string[]? selectionArgs,
        string? sortOrder)
    {
        if (!TryResolve(uri, out var asset) || asset == null)
            return null;

        var cols = projection is { Length: > 0 }
            ? projection
            : new[] { IOpenableColumns.DisplayName, IOpenableColumns.Size };

        var cursor = new MatrixCursor(cols, 1);
        var row = new Java.Lang.Object[cols.Length];
        for (int i = 0; i < cols.Length; i++)
        {
            row[i] = (cols[i] switch
            {
                IOpenableColumns.DisplayName => new Java.Lang.String(asset.FileName),
                IOpenableColumns.Size => Java.Lang.Long.ValueOf(asset.Data.LongLength),
                _ => null!
            })!;
        }
        cursor.AddRow(row);
        return cursor;
    }

    public override ParcelFileDescriptor? OpenFile(global::Android.Net.Uri uri, string mode)
    {
        if (!TryResolve(uri, out var asset) || asset == null)
            throw new Java.IO.FileNotFoundException($"Ephemeral asset missing or expired: {uri}");

        var pipe = ParcelFileDescriptor.CreatePipe();
        if (pipe == null || pipe.Length < 2)
            throw new IOException("Unable to allocate volatile ParcelFileDescriptor pipe.");

        var readEnd = pipe[0];
        var writeEnd = pipe[1];
        var payload = asset.Data;

        _ = Task.Run(() =>
        {
            using var stream = new ParcelFileDescriptor.AutoCloseOutputStream(writeEnd);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        });

        return readEnd;
    }

    public override global::Android.Net.Uri? Insert(global::Android.Net.Uri uri, ContentValues? values) =>
        throw new Java.Lang.UnsupportedOperationException("Read-only ephemeral mediation provider.");

    public override int Update(global::Android.Net.Uri uri, ContentValues? values, string? selection, string[]? selectionArgs) => 0;

    public override int Delete(global::Android.Net.Uri uri, string? selection, string[]? selectionArgs)
    {
        var token = ExtractToken(uri);
        return token != null && VolatileStore.TryRemove(token, out _) ? 1 : 0;
    }

    private static bool TryResolve(global::Android.Net.Uri uri, out EphemeralAsset? asset)
    {
        PruneExpired();
        var token = ExtractToken(uri);
        if (token != null && VolatileStore.TryGetValue(token, out var found) && found.ExpiresUtc > DateTime.UtcNow)
        {
            asset = found;
            return true;
        }
        asset = null;
        return false;
    }

    private static string? ExtractToken(global::Android.Net.Uri uri)
    {
        var segs = uri.PathSegments;
        return segs != null && segs.Count >= 1 ? segs[0] : null;
    }

    private static void PruneExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kvp in VolatileStore)
        {
            if (kvp.Value.ExpiresUtc <= now)
                VolatileStore.TryRemove(kvp.Key, out _);
        }
    }
}
