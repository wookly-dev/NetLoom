using System.Net;
using System.Text.Json;
using NetLoom.App.Models;
using System.IO;

namespace NetLoom.App.Services;

/// <summary>
/// Offline analyst policy. It is intentionally local-only: no allowlist or asset information is
/// sent to an external service. Address entries may be a single IPv4 address or CIDR.
/// </summary>
public sealed class SecurityPolicyService
{
    private readonly object _sync = new();
    private SecurityPolicyDocument _document;

    public SecurityPolicyService()
    {
        _document = LoadCore();
    }

    public string StoragePath
    {
        get
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(root, "WooklyDev", "NetLoom", "security-policy.json");
        }
    }

    public SecurityPolicyDocument Snapshot()
    {
        lock (_sync)
        {
            return new SecurityPolicyDocument
            {
                SchemaVersion = _document.SchemaVersion,
                UpdatedUtc = _document.UpdatedUtc,
                TrustedInternalAddresses = _document.TrustedInternalAddresses.ToList(),
                AllowedExternalAddresses = _document.AllowedExternalAddresses.ToList(),
                AllowedDomains = _document.AllowedDomains.ToList(),
                AllowedServiceGroups = _document.AllowedServiceGroups.ToList(),
                AllowedExternalPorts = _document.AllowedExternalPorts.ToList(),
                DnsMinimumQueries = _document.DnsMinimumQueries,
                DnsNxDomainRatioPercent = _document.DnsNxDomainRatioPercent,
                DnsLongQueryLength = _document.DnsLongQueryLength,
                DnsLongQueryCount = _document.DnsLongQueryCount
            };
        }
    }

    public void Save(SecurityPolicyDocument document)
    {
        document ??= new SecurityPolicyDocument();
        document.SchemaVersion = 1;
        document.UpdatedUtc = DateTime.UtcNow;
        document.TrustedInternalAddresses = NormalizeLines(document.TrustedInternalAddresses);
        document.AllowedExternalAddresses = NormalizeLines(document.AllowedExternalAddresses);
        document.AllowedDomains = NormalizeLines(document.AllowedDomains).Select(NormalizeDomain).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        document.AllowedServiceGroups = NormalizeLines(document.AllowedServiceGroups);
        document.AllowedExternalPorts = document.AllowedExternalPorts.Where(p => p is > 0 and <= 65535).Distinct().OrderBy(p => p).ToList();
        document.DnsMinimumQueries = Math.Clamp(document.DnsMinimumQueries, 5, 10000);
        document.DnsNxDomainRatioPercent = Math.Clamp(document.DnsNxDomainRatioPercent, 5, 100);
        document.DnsLongQueryLength = Math.Clamp(document.DnsLongQueryLength, 40, 253);
        document.DnsLongQueryCount = Math.Clamp(document.DnsLongQueryCount, 1, 1000);

        string path = StoragePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true }));
        lock (_sync) _document = document;
    }

    public void Reload()
    {
        var loaded = LoadCore();
        lock (_sync) _document = loaded;
    }

    public bool IsTrustedInternal(string ip)
    {
        lock (_sync) return _document.TrustedInternalAddresses.Any(entry => AddressMatches(entry, ip));
    }

    public bool IsExternalAllowed(string ip, string? host = null, string? serviceGroup = null, int? port = null)
    {
        lock (_sync)
        {
            if (_document.AllowedExternalAddresses.Any(entry => AddressMatches(entry, ip))) return true;
            string domain = NormalizeDomain(host);
            if (domain.Length > 0 && _document.AllowedDomains.Any(allowed => DomainMatches(domain, allowed))) return true;
            if (!string.IsNullOrWhiteSpace(serviceGroup) && _document.AllowedServiceGroups.Any(g => string.Equals(g.Trim(), serviceGroup.Trim(), StringComparison.OrdinalIgnoreCase))) return true;
            if (port.HasValue && _document.AllowedExternalPorts.Contains(port.Value)) return true;
            return false;
        }
    }

    public bool IsDomainAllowed(string host)
    {
        string domain = NormalizeDomain(host);
        if (domain.Length == 0) return false;
        lock (_sync) return _document.AllowedDomains.Any(allowed => DomainMatches(domain, allowed));
    }

    public (int MinimumQueries, int NxDomainRatioPercent, int LongQueryLength, int LongQueryCount) DnsThresholds
    {
        get
        {
            lock (_sync)
                return (_document.DnsMinimumQueries, _document.DnsNxDomainRatioPercent, _document.DnsLongQueryLength, _document.DnsLongQueryCount);
        }
    }

    private SecurityPolicyDocument LoadCore()
    {
        try
        {
            if (!File.Exists(StoragePath)) return new SecurityPolicyDocument();
            SecurityPolicyDocument document = JsonSerializer.Deserialize<SecurityPolicyDocument>(File.ReadAllText(StoragePath))
                ?? new SecurityPolicyDocument();
            document.TrustedInternalAddresses ??= new();
            document.AllowedExternalAddresses ??= new();
            document.AllowedDomains ??= new();
            document.AllowedServiceGroups ??= new();
            document.AllowedExternalPorts ??= new();
            return document;
        }
        catch
        {
            return new SecurityPolicyDocument();
        }
    }

    private static List<string> NormalizeLines(IEnumerable<string>? values) => (values ?? Array.Empty<string>())
        .Select(v => v?.Trim() ?? "")
        .Where(v => v.Length > 0 && !v.StartsWith('#'))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static bool DomainMatches(string domain, string allowed)
    {
        string normalized = NormalizeDomain(allowed);
        if (normalized.Length == 0) return false;
        return domain.Equals(normalized, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + normalized, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        string domain = value.Trim().Trim('.').ToLowerInvariant();
        if (domain.StartsWith("*.")) domain = domain[2..];
        return domain;
    }

    public static bool IsValidAddressEntry(string? entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return false;
        string value = entry.Trim();
        int slash = value.IndexOf('/');
        if (slash < 0)
            return IPAddress.TryParse(value, out var single) && single.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

        if (value.IndexOf('/', slash + 1) >= 0) return false;
        if (!IPAddress.TryParse(value[..slash], out var networkIp) || networkIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        return int.TryParse(value[(slash + 1)..], out int prefix) && prefix is >= 0 and <= 32;
    }

    public static bool AddressMatches(string entry, string ipText)
    {
        if (!IPAddress.TryParse(ipText, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        string value = entry.Trim();
        int slash = value.IndexOf('/');
        if (slash < 0)
            return IPAddress.TryParse(value, out var single) && single.Equals(ip);

        if (!IPAddress.TryParse(value[..slash], out var networkIp) || networkIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        if (!int.TryParse(value[(slash + 1)..], out int prefix) || prefix is < 0 or > 32) return false;
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint addr = ToUInt32(ip);
        uint network = ToUInt32(networkIp);
        return (addr & mask) == (network & mask);
    }

    internal static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
