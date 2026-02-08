namespace CFScanner.Utils;

/// <summary>
/// Utility methods for locating and verifying the Xray executable.
/// </summary>
public static class XrayUtils
{
    /// <summary>
    /// Attempts to locate the Xray executable in the application's base directory.
    /// Checks for platform-specific filenames (xray.exe on Windows, xray on Unix).
    /// </summary>
    /// <returns>Full path to the executable if found; otherwise, null.</returns>
    public static string? ResolveXrayExecutable()
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

    /// <summary>
    /// Ensures the given file has executable permissions on Unix-like systems.
    /// On Windows this check is skipped and always returns true.
    /// </summary>
    /// <param name="path">Path to the executable.</param>
    /// <returns>True if the file is executable or the platform is Windows; otherwise false.</returns>
    public static bool EnsureExecutablePermission(string path)
    {
        if (OperatingSystem.IsWindows()) return true;
        try
        {
            // FileInfo is not needed for GetUnixFileMode; we keep it for potential future use.
            var mode = File.GetUnixFileMode(path);
            bool isExecutable = mode.HasFlag(UnixFileMode.UserExecute) ||
                                mode.HasFlag(UnixFileMode.GroupExecute) ||
                                mode.HasFlag(UnixFileMode.OtherExecute);
            return isExecutable;
        }
        catch
        {
            return false;
        }
    }
}