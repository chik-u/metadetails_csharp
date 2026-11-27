using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace MetaGuard.Desktop;

/// <summary>
/// Registers and unregisters per-user Windows Explorer context menu entries and
/// "Send to" shortcuts so right-click sharing invokes MetaGuard in-memory mediation.
/// </summary>
public static class ShellIntegration
{
    private const string RegistryVerbPath = @"Software\Classes\*\shell\MetaGuardMediate";

    public static string SendToShortcutPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.SendTo),
        "MetaGuard Share Mediator.lnk");

    public static bool IsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegistryVerbPath, writable: false);
        return key != null || File.Exists(SendToShortcutPath);
    }

    public static void Install(string? exePath = null)
    {
        var targetExe = string.IsNullOrWhiteSpace(exePath) ? Environment.ProcessPath : exePath;
        if (string.IsNullOrWhiteSpace(targetExe))
            throw new InvalidOperationException("Cannot determine MetaGuard.Desktop executable path.");

        using (var key = Registry.CurrentUser.CreateSubKey(RegistryVerbPath))
        {
            key.SetValue(null, "Sanitize && Share via MetaGuard (Zero-Transit)");
            key.SetValue("Icon", $"{targetExe},0");
            using var cmd = key.CreateSubKey("command");
            cmd.SetValue(null, $"\"{targetExe}\" \"%1\"");
        }

        CreateShortcut(SendToShortcutPath, targetExe, "Zero-transit OS metadata mediation prior to sharing");
    }

    public static void Uninstall()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(RegistryVerbPath, throwOnMissingSubKey: false); }
        catch { }

        try
        {
            if (File.Exists(SendToShortcutPath))
                File.Delete(SendToShortcutPath);
        }
        catch { }
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string description)
    {
        var dir = Path.GetDirectoryName(shortcutPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var shellType = Type.GetTypeFromProgID("WScript.Shell");
        if (shellType == null) return;

        object? shell = null;
        object? shortcut = null;
        try
        {
            shell = Activator.CreateInstance(shellType);
            if (shell == null) return;
            shortcut = shellType.InvokeMember(
                "CreateShortcut",
                System.Reflection.BindingFlags.InvokeMethod,
                null,
                shell,
                [shortcutPath]);
            if (shortcut == null) return;

            var scType = shortcut.GetType();
            scType.InvokeMember("TargetPath", System.Reflection.BindingFlags.SetProperty, null, shortcut, [targetPath]);
            scType.InvokeMember("Description", System.Reflection.BindingFlags.SetProperty, null, shortcut, [description]);
            scType.InvokeMember("WorkingDirectory", System.Reflection.BindingFlags.SetProperty, null, shortcut, [Path.GetDirectoryName(targetPath) ?? string.Empty]);
            scType.InvokeMember("Save", System.Reflection.BindingFlags.InvokeMethod, null, shortcut, null);
        }
        finally
        {
            if (shortcut != null && Marshal.IsComObject(shortcut)) Marshal.ReleaseComObject(shortcut);
            if (shell != null && Marshal.IsComObject(shell)) Marshal.ReleaseComObject(shell);
        }
    }
}
