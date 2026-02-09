using CFScanner.Core;
using CFScanner.UI;

namespace CFScanner.Utils;

public static class XraySetup
{
    public static async Task<bool> InitializeAsync()
    {
        string? xrayPath = ResolveXrayExecutable();
        if (xrayPath == null)
        {
            ConsoleInterface.PrintError("Xray executable not found.");
            Console.WriteLine(" Xray is required for V2Ray verification.");
            Console.WriteLine(" Please download Xray from https://github.com/XTLS/Xray-core/releases/");
            return false;
        }

        if (!EnsureExecutablePermission(xrayPath))
        {
            ConsoleInterface.PrintError("Xray exists but is not executable.");
            Console.WriteLine($" Please run: chmod +x \"{xrayPath}\"");
            return false;
        }

        Defaults.XrayExeName = xrayPath;

        if (!await V2RayController.ValidateXrayConfigAsync(GlobalContext.Config.V2RayConfigPath!))
        {
            ConsoleInterface.PrintError("Xray configuration validation failed.");
            return false;
        }

        GlobalContext.RawV2RayTemplate = await File.ReadAllTextAsync(GlobalContext.Config.V2RayConfigPath!);
        return true;
    }

    private static string? ResolveXrayExecutable()
    {
        string baseDir = AppContext.BaseDirectory;
        if (OperatingSystem.IsWindows())
        {
            string winPath = Path.Combine(baseDir, "xray.exe");
            if (File.Exists(winPath)) return winPath;
        }
        string unixPath = Path.Combine(baseDir, "xray");
        if (File.Exists(unixPath)) return unixPath;
        return null;
    }

    private static bool EnsureExecutablePermission(string path)
    {
        if (OperatingSystem.IsWindows()) return true;
        try
        {
            var mode = File.GetUnixFileMode(path);
            return mode.HasFlag(UnixFileMode.UserExecute) ||
                   mode.HasFlag(UnixFileMode.GroupExecute) ||
                   mode.HasFlag(UnixFileMode.OtherExecute);
        }
        catch { return false; }
    }
}