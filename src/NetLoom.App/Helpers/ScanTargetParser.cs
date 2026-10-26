using System.Net;
using System.Net.Sockets;

namespace NetLoom.App.Helpers;

public sealed class ScanTargetGroupDefinition
{
    public string GroupLabel { get; init; } = "";
    public string Expression { get; init; } = "";
    public IReadOnlyList<IPAddress> Hosts { get; init; } = Array.Empty<IPAddress>();
    public int PrefixLengthHint { get; init; } = 24;
    public bool IsPrivateOrLocal { get; init; }
}

public sealed class ScanTargetDefinition
{
    public IReadOnlyList<IPAddress> Hosts { get; init; } = Array.Empty<IPAddress>();
    public IReadOnlyList<ScanTargetGroupDefinition> Groups { get; init; } = Array.Empty<ScanTargetGroupDefinition>();
    public string DisplayText { get; init; } = "";
    public string NormalizedExpression { get; init; } = "";
    public bool IsPrivateOrLocal { get; init; }
}

public static class ScanTargetParser
{
    public static ScanTargetDefinition Parse(string expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
            throw new ArgumentException("스캔 범위를 입력하거나 범위 선택 버튼을 사용하세요.");

        var parts = expression
            .Replace("\r", "\n")
            .Split(new[] { '\n', ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (parts.Length == 0)
            throw new ArgumentException("스캔 대상 주소가 없습니다.");

        var hosts = new List<IPAddress>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var groups = new List<ScanTargetGroupDefinition>();
        bool privateOrLocal = true;

        for (int index = 0; index < parts.Length; index++)
        {
            var item = ParseSingle(parts[index]);
            privateOrLocal &= item.IsPrivateOrLocal;

            var uniqueHosts = new List<IPAddress>();
            foreach (var ip in item.Hosts)
            {
                if (!seen.Add(ip.ToString()))
                    continue;

                uniqueHosts.Add(ip);
                hosts.Add(ip);

                if (hosts.Count > CidrHelper.MaxHosts)
                    throw new ArgumentException($"다중 범위를 합쳐 최대 {CidrHelper.MaxHosts:N0}개 주소까지만 스캔할 수 있습니다.");
            }

            if (uniqueHosts.Count == 0)
                continue;

            groups.Add(new ScanTargetGroupDefinition
            {
                GroupLabel = $"대역 {GroupLetter(groups.Count)}",
                Expression = item.DisplayText,
                Hosts = uniqueHosts,
                PrefixLengthHint = item.PrefixLengthHint,
                IsPrivateOrLocal = item.IsPrivateOrLocal
            });
        }

        if (hosts.Count == 0)
            throw new ArgumentException("스캔 대상 주소가 없습니다.");

        string normalized = string.Join(Environment.NewLine, groups.Select(g => g.Expression));
        string display = groups.Count == 1
            ? groups[0].Expression
            : $"{groups.Count:N0}개 감사 대역 · {hosts.Count:N0} IP";

        return new ScanTargetDefinition
        {
            Hosts = hosts,
            Groups = groups,
            DisplayText = display,
            NormalizedExpression = normalized,
            IsPrivateOrLocal = privateOrLocal
        };
    }

    private sealed class ParsedSingle
    {
        public IReadOnlyList<IPAddress> Hosts { get; init; } = Array.Empty<IPAddress>();
        public string DisplayText { get; init; } = "";
        public int PrefixLengthHint { get; init; } = 24;
        public bool IsPrivateOrLocal { get; init; }
    }

    private static ParsedSingle ParseSingle(string expression)
    {
        var value = expression.Trim();

        if (value.Contains('/'))
        {
            var hosts = CidrHelper.EnumerateHosts(value);
            var prefix = int.Parse(value.Split('/')[1]);
            return new ParsedSingle
            {
                Hosts = hosts,
                DisplayText = value,
                PrefixLengthHint = prefix,
                IsPrivateOrLocal = hosts.Count == 0 || hosts.All(CidrHelper.IsPrivateOrLocal)
            };
        }

        var rangeParts = value.Split('-', 2, StringSplitOptions.TrimEntries);
        if (rangeParts.Length == 2)
        {
            if (!TryIPv4(rangeParts[0], out var start) || !TryIPv4(rangeParts[1], out var end))
                throw new ArgumentException("IP 범위 형식이 올바르지 않습니다. 예: 192.168.0.10 - 192.168.0.100");

            var hosts = EnumerateRange(start!, end!);
            return new ParsedSingle
            {
                Hosts = hosts,
                DisplayText = $"{start} - {end}",
                PrefixLengthHint = GuessPrefix(start!, end!),
                IsPrivateOrLocal = CidrHelper.IsPrivateOrLocal(start!) && CidrHelper.IsPrivateOrLocal(end!)
            };
        }

        if (TryIPv4(value, out var single))
        {
            return new ParsedSingle
            {
                Hosts = new[] { single! },
                DisplayText = single!.ToString(),
                PrefixLengthHint = 32,
                IsPrivateOrLocal = CidrHelper.IsPrivateOrLocal(single!)
            };
        }

        throw new ArgumentException("스캔 범위 형식이 올바르지 않습니다. CIDR, 단일 IP, 시작-끝 IP 형식을 사용할 수 있습니다.");
    }

    private static IReadOnlyList<IPAddress> EnumerateRange(IPAddress start, IPAddress end)
    {
        uint a = ToUInt32(start);
        uint b = ToUInt32(end);
        if (b < a)
            throw new ArgumentException("끝 IP는 시작 IP보다 크거나 같아야 합니다.");

        long count = (long)b - a + 1;
        if (count > CidrHelper.MaxHosts)
            throw new ArgumentException($"한 번에 최대 {CidrHelper.MaxHosts:N0}개 주소까지만 스캔할 수 있습니다.");

        var list = new List<IPAddress>((int)count);
        for (uint current = a; ; current++)
        {
            list.Add(FromUInt32(current));
            if (current == b) break;
        }
        return list;
    }

    private static int GuessPrefix(IPAddress start, IPAddress end)
    {
        var a = start.GetAddressBytes();
        var b = end.GetAddressBytes();
        if (a[0] == b[0] && a[1] == b[1] && a[2] == b[2]) return 24;
        if (a[0] == b[0] && a[1] == b[1]) return 16;
        if (a[0] == b[0]) return 8;
        return 0;
    }

    private static bool TryIPv4(string value, out IPAddress? ip)
    {
        if (IPAddress.TryParse(value.Trim(), out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            ip = parsed;
            return true;
        }
        ip = null;
        return false;
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static IPAddress FromUInt32(uint value) => new(new byte[]
    {
        (byte)(value >> 24),
        (byte)(value >> 16),
        (byte)(value >> 8),
        (byte)value
    });

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
