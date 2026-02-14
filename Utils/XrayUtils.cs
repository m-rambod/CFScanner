using CFScanner.Core;
using CFScanner.UI;

namespace CFScanner.Utils;

/// <summary>
/// Provides initialization and validation logic for the Xray executable
/// required for V2Ray (XTLS) verification. 
/// Handles locating the binary, ensuring execution permissions, 
/// and validating the user's Xray configuration file.
/// </summary>
public static class XraySetup
{
    /// <summary>
    /// Initializes the Xray subsystem:
    /// - Detects the Xray binary for the current OS.
    /// - Ensures executable permissions (Linux/macOS).
    /// - Validates the provided V2Ray/Xray configuration file.
    /// - Loads the raw config template for dynamic IP/port injection.
    /// </summary>
    /// <returns>
    /// True if initialization succeeds and Xray is ready for use;
    /// False if any required step fails.
    /// </returns>
    public static async Task<bool> InitializeAsync()
    {
        // 1. Locate the Xray executable (platform-dependent)
        string? xrayPath = ResolveXrayExecutable();
        if (xrayPath == null)
        {
            ConsoleInterface.PrintError("Xray executable not found.");
            Console.WriteLine(" Xray is required for V2Ray verification.");
            Console.WriteLine(" Please download Xray from https://github.com/XTLS/Xray-core/releases/");
            return false;
        }

        // 2. Verify that the file is executable (Unix systems only)
        if (!EnsureExecutablePermission(xrayPath))
        {
            ConsoleInterface.PrintError("Xray exists but is not executable.");
            Console.WriteLine($" Please run: chmod +x \"{xrayPath}\"");
            return false;
        }

        // 3. Store resolved binary name in Defaults for downstream usage
        Defaults.XrayExeName = xrayPath;

        // 4. Validate the user-provided Xray JSON config 
        if (!await V2RayController.ValidateXrayConfigAsync(GlobalContext.Config.V2RayConfigPath!))
        {
            ConsoleInterface.PrintError("Xray configuration validation failed.");
            return false;
        }

        // 5. Load the raw template to be dynamically patched per IP/Port later
        GlobalContext.RawV2RayTemplate = await File.ReadAllTextAsync(GlobalContext.Config.V2RayConfigPath!);
        return true;
    }

    /// <summary>
    /// Determines the correct Xray executable filename depending on the current OS.
    /// Checks the application's base directory for "xray.exe" (Windows) 
    /// or "xray" (Linux/macOS).
    /// </summary>
    /// <returns>
    /// The full path to the executable if found; otherwise null.
    /// </returns>
    private static string? ResolveXrayExecutable()
    {
        string baseDir = AppContext.BaseDirectory;

        // Windows executable
        if (OperatingSystem.IsWindows())
        {
            string winPath = Path.Combine(baseDir, "xray.exe");
            if (File.Exists(winPath))
                return winPath;
        }

        // Unix-like executable 
        string unixPath = Path.Combine(baseDir, "xray");
        if (File.Exists(unixPath))
            return unixPath;

        return null;
    }

    /// <summary>
    /// Ensures the located Xray binary has the appropriate executable 
    /// permission bits on Unix-like systems.
    /// Windows does not require permission checks and always returns true.
    /// </summary>
    /// <param name="path">Full path to the Xray binary.</param>
    /// <returns>
    /// True if executable or running on Windows; otherwise false.
    /// </returns>
    private static bool EnsureExecutablePermission(string path)
    {
        if (OperatingSystem.IsWindows())
            return true; // Windows does not use UNIX exec bits

        try
        {
            var mode = File.GetUnixFileMode(path);

            // Check execute permission for any of the user/group/other flags
            return mode.HasFlag(UnixFileMode.UserExecute) ||
                   mode.HasFlag(UnixFileMode.GroupExecute) ||
                   mode.HasFlag(UnixFileMode.OtherExecute);
        }
        catch
        {
            // Could not read file mode -> treat as non-executable
            return false;
        }
    }
}