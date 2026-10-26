using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NetLoom.App.Helpers;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class NestedNetworkDiscoveryService
{
    private static readonly Regex RouteRowRegex = new(
        @"^\s*(?<dest>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mask>\d{1,3}(?:\.\d{1,3}){3})\s+(?<gateway>\S+)\s+(?<iface>\d{1,3}(?:\.\d{1,3}){3})\s+(?<metric>\d+)\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<NestedNetworkInfo> Discover(
        IEnumerable<ScanResult> results,
        AdapterInfo? adapter,
        IReadOnlyList<ScanTargetGroupDefinition> currentGroups)
    {
        var windowsRoutes = GetExplicitWindowsRoutes(adapter);
        var currentCidrs = currentGroups
            .Where(g => g.Expression.Contains('/'))
            .Select(g => NormalizeCidr(g.Expression))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var map = new Dictionary<string, NestedNetworkInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var result in results.Where(r => r.IsOnline && r.SnmpInfo.Success))
        {
            bool strongParent = result.DeviceType is DeviceType.Router or DeviceType.Firewall or DeviceType.Switch or DeviceType.AccessPoint or DeviceType.WifiExtender;
            bool forwardingConfirmed = string.Equals(result.SnmpInfo.IpForwarding, "1", StringComparison.Ordinal);
            if (!strongParent && !result.IsGateway && !forwardingConfirmed)
                continue;

            foreach (var iface in result.SnmpInfo.Ipv4Interfaces)
            {
                if (!IsUsablePrivateCidr(iface.Cidr)) continue;
                string cidr = NormalizeCidr(iface.Cidr);
                if (string.IsNullOrWhiteSpace(cidr)) continue;
                if (IsSameSubnetAsHost(cidr, result.IpAddress)) continue;

                AddCandidate(map, result, cidr, iface.Address, "", "SNMP 인터페이스",
                    $"{result.IpAddress} 장비가 직접 연결 IPv4 인터페이스 {iface.Address} ({cidr})를 보고했습니다.",
                    currentCidrs, windowsRoutes);
            }

            foreach (var route in result.SnmpInfo.Routes)
            {
                if (!IsUsablePrivateCidr(route.Cidr)) continue;
                string cidr = NormalizeCidr(route.Cidr);
                if (string.IsNullOrWhiteSpace(cidr)) continue;
                if (IsSameSubnetAsHost(cidr, result.IpAddress)) continue;

                AddCandidate(map, result, cidr, "", route.NextHop, "SNMP 라우트",
                    string.IsNullOrWhiteSpace(route.NextHop) || route.NextHop == "0.0.0.0"
                        ? $"{result.IpAddress} 장비의 IPv4 라우팅 테이블에서 {cidr} 대역을 발견했습니다."
                        : $"{result.IpAddress} 장비가 {cidr} 대역을 Next Hop {route.NextHop} 경유로 보고했습니다.",
                    currentCidrs, windowsRoutes);
            }
        }

        return map.Values
            .OrderBy(n => n.Reachability)
            .ThenBy(n => IpSortKey(n.ParentIp))
            .ThenBy(n => IpSortKey(n.Cidr.Split('/')[0]))
            .ToArray();
    }

    public static IReadOnlyList<SubnetRecommendation> ToRecommendations(IEnumerable<NestedNetworkInfo> nested)
    {
        return nested
            .Where(n => !n.IsCurrentScope)
            .Select((n, i) => new SubnetRecommendation
            {
                IsSelected = false,
                GroupLabel = $"하위 {GroupLetter(i)}",
                Cidr = n.Cidr,
                Source = n.Source,
                Gateway = n.ParentIp,
                InterfaceAddress = n.InterfaceAddress,
                Reason = $"{n.ParentDisplay} · {n.ReachabilityText}\n{n.Reason}",
                EstimatedHosts = n.EstimatedHosts,
                ParentDevice = n.ParentDisplay,
                Reachability = n.ReachabilityText
            })
            .ToArray();
    }

    private static void AddCandidate(
        IDictionary<string, NestedNetworkInfo> map,
        ScanResult parent,
        string cidr,
        string interfaceAddress,
        string nextHop,
        string source,
        string reason,
        ISet<string> currentCidrs,
        ISet<string> windowsRoutes)
    {
        if (cidr is "0.0.0.0/0" or "255.255.255.255/32") return;
        string key = $"{parent.IpAddress}|{cidr}";
        if (map.ContainsKey(key)) return;

        var reachability = currentCidrs.Contains(cidr)
            ? NestedNetworkReachability.CurrentScope
            : windowsRoutes.Contains(cidr)
                ? NestedNetworkReachability.Routed
                : NestedNetworkReachability.DiscoveredOnly;

        map[key] = new NestedNetworkInfo
        {
            ParentIp = parent.IpAddress,
            ParentHost = parent.HostName,
            ParentDeviceType = parent.DeviceType,
            Cidr = cidr,
            InterfaceAddress = interfaceAddress,
            NextHop = nextHop,
            Source = source,
            Reason = reason,
            Reachability = reachability,
            EstimatedHosts = EstimateHosts(cidr)
        };
    }

    private static HashSet<string> GetExplicitWindowsRoutes(AdapterInfo? adapter)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows() || adapter is null) return set;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "route.exe",
                Arguments = "PRINT -4",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process is null) return set;
            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(2500))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return set;
            }

            foreach (var rawLine in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var match = RouteRowRegex.Match(rawLine);
                if (!match.Success) continue;
                string destination = match.Groups["dest"].Value;
                string mask = match.Groups["mask"].Value;
                string gateway = match.Groups["gateway"].Value;
                string iface = match.Groups["iface"].Value;

                if (!IPAddress.TryParse(destination, out var destIp) || destIp.AddressFamily != AddressFamily.InterNetwork ||
                    !IPAddress.TryParse(mask, out var maskIp) || maskIp.AddressFamily != AddressFamily.InterNetwork)
                    continue;

                int prefix = MaskToPrefix(maskIp);
                if (prefix < 8 || prefix > 30) continue;
                if (!IsPrivate(destIp)) continue;

                bool selectedInterface = string.Equals(iface, adapter.Address, StringComparison.OrdinalIgnoreCase);
                bool selectedGateway = !string.IsNullOrWhiteSpace(adapter.GatewayAddress) &&
                                       string.Equals(gateway, adapter.GatewayAddress, StringComparison.OrdinalIgnoreCase);
                if (!selectedInterface && !selectedGateway) continue;

                string cidr = BuildNetworkCidr(destIp, prefix);
                set.Add(cidr);
            }
        }
        catch
        {
        }

        return set;
    }

    private static bool IsUsablePrivateCidr(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out int prefix))
            return false;
        if (prefix < 8 || prefix > 30) return false;
        if (!IsPrivate(ip)) return false;
        var b = ip.GetAddressBytes();
        return b[0] != 127 && !(b[0] == 169 && b[1] == 254);
    }

    private static bool IsSameSubnetAsHost(string cidr, string hostIp)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out int prefix) ||
            !IPAddress.TryParse(hostIp, out var host))
            return false;
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (ToUInt32(network) & mask) == (ToUInt32(host) & mask);
    }

    private static string NormalizeCidr(string value)
    {
        var parts = value.Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32)
            return "";
        return BuildNetworkCidr(ip, prefix);
    }

    private static string BuildNetworkCidr(IPAddress address, int prefix)
    {
        uint value = ToUInt32(address);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint network = value & mask;
        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefix}";
    }

    private static int MaskToPrefix(IPAddress mask)
    {
        uint value = ToUInt32(mask);
        int prefix = 0;
        bool zeroSeen = false;
        for (int bit = 31; bit >= 0; bit--)
        {
            bool one = (value & (1u << bit)) != 0;
            if (one && zeroSeen) return -1;
            if (one) prefix++;
            else zeroSeen = true;
        }
        return prefix;
    }

    private static bool IsPrivate(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b[0] == 10 ||
               (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
               (b[0] == 192 && b[1] == 168);
    }

    private static int EstimateHosts(string cidr)
    {
        if (!int.TryParse(cidr.Split('/').LastOrDefault(), out int prefix) || prefix < 0 || prefix > 32)
            return 0;
        long total = 1L << (32 - prefix);
        long usable = prefix >= 31 ? total : Math.Max(0, total - 2);
        return usable > int.MaxValue ? int.MaxValue : (int)usable;
    }

    private static uint IpSortKey(string value)
    {
        string ipText = value.Contains('/') ? value.Split('/')[0] : value;
        return IPAddress.TryParse(ipText, out var ip) ? ToUInt32(ip) : uint.MaxValue;
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return uint.MaxValue;
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static string GroupLetter(int index)
    {
        index = Math.Max(0, index);
        var chars = new Stack<char>();
        do
        {
            chars.Push((char)('A' + (index % 26)));
            index = index / 26 - 1;
        } while (index >= 0);
        return new string(chars.ToArray());
    }
}
