using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class NetworkScopeDiscoveryService
{
    private static readonly Regex RouteRowRegex = new(
        @"^\s*(?<dest>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mask>\d{1,3}(?:\.\d{1,3}){3})\s+(?<gateway>\S+)\s+(?<iface>\d{1,3}(?:\.\d{1,3}){3})\s+(?<metric>\d+)\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<SubnetRecommendation> GetRecommendations(AdapterInfo adapter)
    {
        var candidates = new Dictionary<string, SubnetRecommendation>(StringComparer.OrdinalIgnoreCase);

        AddCandidate(
            candidates,
            BuildNetworkCidr(adapter.Address, adapter.PrefixLength),
            "직접 연결",
            adapter.GatewayAddress,
            adapter.Address,
            "선택한 어댑터의 직접 연결 IPv4 대역",
            selected: true);

        // Surface every active private IPv4 interface, not only interfaces sharing the selected gateway.
        // A workstation can be attached to multiple routed/VLAN/NAT segments at the same time (for example
        // Ethernet 192.168.123.0/24 plus Wi-Fi 192.168.0.0/24). Those networks are genuinely reachable
        // from this audit PC and should be offered as candidates, while remaining unselected by default.
        IReadOnlyList<AdapterInfo> activeAdapters = Array.Empty<AdapterInfo>();
        try
        {
            activeAdapters = NetworkAdapterService.GetAdapters();
            foreach (var peer in activeAdapters)
            {
                if (string.Equals(peer.Address, adapter.Address, StringComparison.OrdinalIgnoreCase)) continue;
                if (!IPAddress.TryParse(peer.Address, out var peerIp) || !IsPrivate(peerIp)) continue;

                bool sameAdapterName = string.Equals(peer.Name, adapter.Name, StringComparison.CurrentCultureIgnoreCase);
                bool sameGateway = !string.IsNullOrWhiteSpace(adapter.GatewayAddress) &&
                                   string.Equals(peer.GatewayAddress, adapter.GatewayAddress, StringComparison.OrdinalIgnoreCase);

                AddCandidate(
                    candidates,
                    BuildNetworkCidr(peer.Address, peer.PrefixLength),
                    sameAdapterName || sameGateway ? "활성 인터페이스" : "다른 활성 어댑터",
                    peer.GatewayAddress,
                    peer.Address,
                    sameAdapterName
                        ? "선택한 네트워크 어댑터에 함께 설정된 IPv4 대역"
                        : sameGateway
                            ? "선택 어댑터와 동일한 기본 게이트웨이를 사용하는 활성 IPv4 대역"
                            : $"현재 PC의 다른 활성 어댑터({peer.Name})에 직접 연결된 사설 IPv4 대역",
                    selected: false);
            }
        }
        catch
        {
        }

        if (!OperatingSystem.IsWindows())
            return Number(candidates.Values);

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
            if (process is null)
                return Number(candidates.Values);

            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(2500))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return Number(candidates.Values);
            }

            foreach (var rawLine in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var match = RouteRowRegex.Match(rawLine);
                if (!match.Success) continue;

                string destination = match.Groups["dest"].Value;
                string mask = match.Groups["mask"].Value;
                string gateway = match.Groups["gateway"].Value;
                string iface = match.Groups["iface"].Value;

                if (!IPAddress.TryParse(destination, out var destIp) || destIp.AddressFamily != AddressFamily.InterNetwork)
                    continue;
                if (!IPAddress.TryParse(mask, out var maskIp) || maskIp.AddressFamily != AddressFamily.InterNetwork)
                    continue;

                int prefix = MaskToPrefix(maskIp);
                if (prefix < 16 || prefix > 30) continue;
                if (!IsPrivate(destIp)) continue;

                bool throughSelectedInterface = string.Equals(iface, adapter.Address, StringComparison.OrdinalIgnoreCase);
                bool throughSelectedGateway = !string.IsNullOrWhiteSpace(adapter.GatewayAddress) &&
                                              string.Equals(gateway, adapter.GatewayAddress, StringComparison.OrdinalIgnoreCase);
                var routeAdapter = activeAdapters.FirstOrDefault(a => string.Equals(a.Address, iface, StringComparison.OrdinalIgnoreCase));
                bool throughAnyActiveInterface = routeAdapter is not null;
                if (!throughSelectedInterface && !throughSelectedGateway && !throughAnyActiveInterface) continue;

                string cidr = BuildNetworkCidr(destination, prefix);
                bool isDirect = string.Equals(cidr, BuildNetworkCidr(adapter.Address, adapter.PrefixLength), StringComparison.OrdinalIgnoreCase);
                bool otherDirect = routeAdapter is not null &&
                                   !throughSelectedInterface &&
                                   string.Equals(cidr, BuildNetworkCidr(routeAdapter.Address, routeAdapter.PrefixLength), StringComparison.OrdinalIgnoreCase);
                string source = isDirect ? "직접 연결" : otherDirect ? "다른 활성 어댑터" : "라우팅 감지";
                string reason = isDirect
                    ? "선택한 어댑터와 동일한 직접 연결 대역"
                    : otherDirect
                        ? $"Windows 라우팅 테이블에서 다른 활성 어댑터({routeAdapter!.Name})에 직접 연결된 사설 대역"
                        : throughSelectedInterface || throughSelectedGateway
                            ? "Windows IPv4 라우팅 테이블에서 선택 어댑터/게이트웨이를 통해 도달 가능한 사설 대역"
                            : $"Windows IPv4 라우팅 테이블에서 활성 어댑터({routeAdapter?.Name ?? iface})를 통해 도달 가능한 사설 대역";

                AddCandidate(
                    candidates,
                    cidr,
                    source,
                    gateway,
                    iface,
                    reason,
                    selected: isDirect);
            }
        }
        catch
        {
            // Recommendation is a convenience feature. Current adapter subnet remains available on failure.
        }

        return Number(candidates.Values);
    }

    private static IReadOnlyList<SubnetRecommendation> Number(IEnumerable<SubnetRecommendation> items)
    {
        var ordered = items
            .OrderBy(i => i.Source == "직접 연결" ? 0 : 1)
            .ThenBy(i => ParseIp(CidrNetwork(i.Cidr)))
            .ToArray();

        var result = new List<SubnetRecommendation>(ordered.Length);
        for (int i = 0; i < ordered.Length; i++)
        {
            var item = ordered[i];
            result.Add(new SubnetRecommendation
            {
                IsSelected = item.IsSelected,
                GroupLabel = $"대역 {GroupLetter(i)}",
                Cidr = item.Cidr,
                Source = item.Source,
                Gateway = item.Gateway,
                InterfaceAddress = item.InterfaceAddress,
                Reason = item.Reason,
                EstimatedHosts = item.EstimatedHosts,
                ParentDevice = item.ParentDevice,
                Reachability = item.Reachability
            });
        }
        return result;
    }

    private static void AddCandidate(
        IDictionary<string, SubnetRecommendation> map,
        string cidr,
        string source,
        string gateway,
        string iface,
        string reason,
        bool selected)
    {
        if (map.ContainsKey(cidr)) return;
        map[cidr] = new SubnetRecommendation
        {
            IsSelected = selected,
            Cidr = cidr,
            Source = source,
            Gateway = gateway,
            InterfaceAddress = iface,
            Reason = reason,
            EstimatedHosts = EstimateHosts(cidr),
            ParentDevice = string.IsNullOrWhiteSpace(gateway) ? "선택 어댑터" : $"Gateway {gateway}",
            Reachability = source == "직접 연결" ? "현재 감사 범위" : "라우팅 확인"
        };
    }

    private static string BuildNetworkCidr(string address, int prefixLength)
    {
        var ip = IPAddress.Parse(address);
        var b = ip.GetAddressBytes();
        uint value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        uint network = value & mask;
        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefixLength}";
    }

    private static int MaskToPrefix(IPAddress mask)
    {
        uint value = ParseIp(mask.ToString());
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

    private static string CidrNetwork(string cidr) => cidr.Split('/')[0];

    private static uint ParseIp(string value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return uint.MaxValue;
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
