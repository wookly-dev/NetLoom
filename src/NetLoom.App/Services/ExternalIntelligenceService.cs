using System.Net;
using NetLoom.App.Models;
using System.IO;

namespace NetLoom.App.Services;

/// <summary>
/// Optional offline CIDR enrichment. The CSV is analyst-supplied and never downloaded or queried
/// automatically. Format: cidr,country,asn,provider,classification.
/// </summary>
public sealed class ExternalIntelligenceService
{
    private readonly object _sync = new();
    private List<ExternalIntelligenceRecord> _records = new();
    private DateTime _loadedWriteUtc;
    private DateTime _lastCheckUtc;

    public ExternalIntelligenceService() => Reload();

    public string StoragePath
    {
        get
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(root, "WooklyDev", "NetLoom", "external-intelligence.csv");
        }
    }

    public int Count { get { lock (_sync) return _records.Count; } }

    public ExternalIntelligenceRecord? Lookup(string ipText)
    {
        MaybeReload();
        if (!IPAddress.TryParse(ipText, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        uint value = SecurityPolicyService.ToUInt32(ip);
        lock (_sync)
        {
            // Records are kept longest-prefix-first at load time, so the first match is the
            // most specific network without sorting on every packet/snapshot lookup.
            return _records.FirstOrDefault(r => (value & r.Mask) == r.Network);
        }
    }

    public void Reload()
    {
        var list = new List<ExternalIntelligenceRecord>();
        DateTime writeUtc = default;
        try
        {
            if (File.Exists(StoragePath))
            {
                writeUtc = File.GetLastWriteTimeUtc(StoragePath);
                foreach (string raw in File.ReadLines(StoragePath))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith('#')) continue;
                    var parts = ParseCsvLine(line);
                    if (parts.Count == 0 || string.Equals(parts[0], "cidr", StringComparison.OrdinalIgnoreCase)) continue;
                    if (!TryParseCidr(parts[0], out uint network, out uint mask, out int prefix)) continue;
                    list.Add(new ExternalIntelligenceRecord
                    {
                        Cidr = parts[0].Trim(),
                        Country = parts.ElementAtOrDefault(1)?.Trim() ?? "",
                        Asn = parts.ElementAtOrDefault(2)?.Trim() ?? "",
                        Provider = parts.ElementAtOrDefault(3)?.Trim() ?? "",
                        Classification = NormalizeClassification(parts.ElementAtOrDefault(4)),
                        PrefixLength = prefix,
                        Network = network,
                        Mask = mask
                    });
                }
            }
        }
        catch
        {
            list.Clear();
        }
        lock (_sync)
        {
            _records = list.OrderByDescending(r => r.PrefixLength).ToList();
            _loadedWriteUtc = writeUtc;
            _lastCheckUtc = DateTime.UtcNow;
        }
    }

    public void EnsureTemplate()
    {
        string path = StoragePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) return;
        File.WriteAllText(path,
            "# NetLoom offline external intelligence\n" +
            "# classification: TRUSTED, WATCH, SUSPICIOUS, UNKNOWN\n" +
            "cidr,country,asn,provider,classification\n" +
            "# 203.0.113.0/24,KR,AS64500,Example Provider,WATCH\n");
        Reload();
    }

    private void MaybeReload()
    {
        if ((DateTime.UtcNow - _lastCheckUtc) < TimeSpan.FromSeconds(15)) return;
        _lastCheckUtc = DateTime.UtcNow;
        try
        {
            DateTime current = File.Exists(StoragePath) ? File.GetLastWriteTimeUtc(StoragePath) : default;
            if (current != _loadedWriteUtc) Reload();
        }
        catch { }
    }

    private static bool TryParseCidr(string value, out uint network, out uint mask, out int prefix)
    {
        network = 0; mask = 0; prefix = 0;
        string[] parts = value.Trim().Split('/');
        if (parts.Length is < 1 or > 2) return false;
        if (!IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        prefix = parts.Length == 2 && int.TryParse(parts[1], out int parsed) ? parsed : 32;
        if (prefix is < 0 or > 32) return false;
        mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        network = SecurityPolicyService.ToUInt32(ip) & mask;
        return true;
    }

    private static string NormalizeClassification(string? value)
    {
        string v = value?.Trim().ToUpperInvariant() ?? "UNKNOWN";
        return v is "TRUSTED" or "WATCH" or "SUSPICIOUS" ? v : "UNKNOWN";
    }

    private static List<string> ParseCsvLine(string line)
    {
        var values = new List<string>();
        var current = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char ch = line[i];
            if (ch == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { current.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (ch == ',' && !quoted) { values.Add(current.ToString()); current.Clear(); }
            else current.Append(ch);
        }
        values.Add(current.ToString());
        return values;
    }
}
