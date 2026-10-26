using System.Net;

namespace NetLoom.App.Models;

public enum NestedNetworkReachability
{
    CurrentScope,
    Routed,
    DiscoveredOnly
}

public sealed class NestedNetworkInfo
{
    public string ParentIp { get; init; } = "";
    public string ParentHost { get; init; } = "";
    public DeviceType ParentDeviceType { get; init; } = DeviceType.Unknown;
    public string Cidr { get; init; } = "";
    public string InterfaceAddress { get; init; } = "";
    public string NextHop { get; init; } = "";
    public string Source { get; init; } = "";
    public string Reason { get; init; } = "";
    public NestedNetworkReachability Reachability { get; init; } = NestedNetworkReachability.DiscoveredOnly;
    public int EstimatedHosts { get; init; }

    public string ParentDisplay
    {
        get
        {
            var host = string.IsNullOrWhiteSpace(ParentHost) ? "" : $" · {ParentHost}";
            return $"{ParentDeviceType.ToDisplayName()} {ParentIp}{host}";
        }
    }

    public string ReachabilityText => Reachability switch
    {
        NestedNetworkReachability.CurrentScope => "현재 감사 범위",
        NestedNetworkReachability.Routed => "라우팅 확인",
        _ => "대역 발견 · 경로 미확인"
    };

    public bool IsCurrentScope => Reachability == NestedNetworkReachability.CurrentScope;
    public bool IsRouteConfirmed => Reachability is NestedNetworkReachability.CurrentScope or NestedNetworkReachability.Routed;
    public string EstimatedHostsText => EstimatedHosts > 0 ? $"{EstimatedHosts:N0} IP" : "-";

    public bool Contains(string ipAddress)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;
        var parts = Cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out int prefix))
            return false;
        if (prefix < 0 || prefix > 32) return false;

        uint ipValue = ToUInt32(ip);
        uint networkValue = ToUInt32(network);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (ipValue & mask) == (networkValue & mask);
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
