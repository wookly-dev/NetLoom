using System.Net;
using System.Net.Sockets;

namespace NetLoom.App.Helpers;

public static class CidrHelper
{
    public const int MaxHosts = 65536;

    public static IReadOnlyList<IPAddress> EnumerateHosts(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr))
            throw new ArgumentException("CIDR을 입력하세요.");

        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out var prefix) ||
            prefix < 0 || prefix > 32)
        {
            throw new ArgumentException("CIDR 형식이 올바르지 않습니다. 예: 192.168.0.0/24");
        }

        uint ipValue = ToUInt32(ip);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        uint network = ipValue & mask;

        long totalAddresses = 1L << (32 - prefix);
        long usableCount = prefix switch
        {
            32 => 1,
            31 => 2,
            _ => totalAddresses - 2
        };

        if (usableCount > MaxHosts)
            throw new ArgumentException($"한 번에 최대 {MaxHosts:N0}개 주소까지만 스캔할 수 있습니다. 범위를 나눠주세요.");

        var list = new List<IPAddress>((int)usableCount);

        if (prefix == 32)
        {
            list.Add(ip);
            return list;
        }

        uint first = prefix == 31 ? network : network + 1;
        uint last = prefix == 31 ? network + 1 : network + (uint)totalAddresses - 2;

        for (uint current = first; ; current++)
        {
            list.Add(FromUInt32(current));
            if (current == last) break;
        }

        return list;
    }

    public static bool IsPrivateOrLocal(string cidr)
    {
        var parts = cidr.Trim().Split('/');
        if (!IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        return IsPrivateOrLocal(ip);
    }

    public static bool IsPrivateOrLocal(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        if (b[0] == 10) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        if (b[0] == 127) return true;
        return false;
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt32(uint value)
    {
        return new IPAddress(new byte[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        });
    }
}
