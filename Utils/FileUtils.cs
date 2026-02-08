using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Utility methods for file I/O: output file management, saving results, loading IP lists, and downloading the ASN database.
/// </summary>
public static class FileUtils
{
    private static readonly object FileLock = new();

    /// <summary>
    /// Creates the output directory and sets the full path of the results file in <see cref="GlobalContext.OutputFilePath"/>.
    /// </summary>
    public static void SetupOutputFile()
    {
        string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "results");
        Directory.CreateDirectory(dir);
        GlobalContext.OutputFilePath = Path.Combine(dir, $"verified_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
    }

    /// <summary>
    /// Appends a successfully verified IP (with optional latency) to the results file, thread‑safe.
    /// </summary>
    /// <param name="ip">IP address.</param>
    /// <param name="latency">Latency in milliseconds.</param>
    public static void SaveResult(string ip, long latency)
    {
        lock (FileLock)
        {
            string line = GlobalContext.Config.SaveLatency ? $"{ip} # {latency}ms" : ip;
            File.AppendAllText(GlobalContext.OutputFilePath, line + Environment.NewLine);
        }
    }

    /// <summary>
    /// Sorts the results file by latency (if the corresponding options are enabled).
    /// </summary>
    public static void SortResultsFile()
    {
        if (!GlobalContext.Config.SortResults ||
            !GlobalContext.Config.SaveLatency ||
            !File.Exists(GlobalContext.OutputFilePath) ||
            GlobalContext.V2RayPassed == 0)
            return;

        Console.WriteLine("\n[Info] Sorting results by latency...");
        try
        {
            var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
            var sortedLines = lines.Select(line =>
            {
                long lat = long.MaxValue;
                var parts = line.Split('#');
                if (parts.Length > 1)
                {
                    var latencyPart = parts[1].Trim().Replace("ms", "");
                    long.TryParse(latencyPart, out lat);
                }
                return new { Line = line, Latency = lat };
            })
            .OrderBy(x => x.Latency)
            .Select(x => x.Line)
            .ToList();

            File.WriteAllLines(GlobalContext.OutputFilePath, sortedLines);
            Console.WriteLine("[Info] Sorting completed.");
        }
        catch
        {
            // Ignore errors during sorting
        }
    }

    /// <summary>
    /// Asynchronously loads IP addresses from a text file.
    /// Each line may be an IPv4 address, a CIDR range, or a comment (starting with #).
    /// CIDRs are expanded using <see cref="NetUtils.ExpandCidr"/>.
    /// </summary>
    /// <param name="path">Path to the input file.</param>
    /// <returns>List of IPAddress objects.</returns>
    public static async Task<List<IPAddress>> LoadIpsAsync(string path)
    {
        var list = new List<IPAddress>();
        await Task.Run(() =>
        {
            foreach (var line in File.ReadLines(path))
            {
                var span = line.AsSpan().Trim();
                if (span.IsEmpty || span.StartsWith("#")) continue;

                // Strip trailing comments or whitespace
                int index = span.IndexOfAny(' ', '\t', '#');
                if (index >= 0) span = span.Slice(0, index);

                var cleanPart = span.ToString();
                if (cleanPart.Contains('/'))
                    list.AddRange(NetUtils.ExpandCidr(cleanPart));
                else if (IPAddress.TryParse(cleanPart, out var ip))
                    list.Add(ip);
            }
        });
        return list;
    }

    /// <summary>
    /// Downloads the compressed ASN database from iptoasn.com, extracts it, and saves it to the given path.
    /// </summary>
    /// <param name="outputPath">Desired path for the extracted TSV file.</param>
    /// <returns>True if download and extraction succeeded; otherwise false.</returns>
    public static bool DownloadAndExtractAsnDb(string outputPath)
    {
        const string url = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
        string gzPath = outputPath + ".gz";
        try
        {
            Console.WriteLine("[Info] Downloading ASN database...");
            using (var handler = new HttpClientHandler())
            using (var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(10) })
            {
                // Set a user agent to avoid being blocked
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

                using var response = client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).Result;
                response.EnsureSuccessStatusCode();
                long? totalBytes = response.Content.Headers.ContentLength;

                using var input = response.Content.ReadAsStreamAsync().Result;
                using var output = File.Create(gzPath);

                var buffer = new byte[64 * 1024];
                long totalRead = 0;
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    totalRead += read;
                    if (totalBytes.HasValue)
                    {
                        double percent = totalRead * 100d / totalBytes.Value;
                        Console.Write($"\r[Download] {percent:0.0}% ");
                    }
                }
            }

            Console.WriteLine("\n[Info] Extracting ASN database...");
            using (var gzStream = new System.IO.Compression.GZipStream(
                File.Open(gzPath, FileMode.Open, FileAccess.Read, FileShare.Read),
                System.IO.Compression.CompressionMode.Decompress))
            using (var outFile = File.Create(outputPath))
            {
                gzStream.CopyTo(outFile);
            }

            File.Delete(gzPath);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[OK] ASN database downloaded and extracted successfully.");
            Console.ResetColor();
            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[Error] ASN download failed: {ex.Message}");
            Console.ResetColor();
            return false;
        }
    }
}