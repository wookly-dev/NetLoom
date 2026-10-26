namespace NetLoom.App.Models;

public sealed class PacketObservation
{
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string SourceIp { get; init; } = "";
    public string DestinationIp { get; init; } = "";
    public string Protocol { get; init; } = "IP";
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public int Length { get; init; }
    public byte TcpFlags { get; init; }
    public string ApplicationSummary { get; init; } = "";
    public string PayloadPreview { get; init; } = "";
    public string InspectionText { get; init; } = "";
    public string DnsQueryName { get; init; } = "";
    public string DnsRecordType { get; init; } = "";
    public bool? DnsIsResponse { get; init; }
    public int? DnsResponseCode { get; init; }
    public bool IsDns => DnsIsResponse.HasValue && !string.IsNullOrWhiteSpace(DnsQueryName);
    public bool IsDnsNxDomain => DnsIsResponse == true && DnsResponseCode == 3;
    public bool IsTcpSyn => string.Equals(Protocol, "TCP", StringComparison.OrdinalIgnoreCase) && (TcpFlags & 0x02) != 0;
    public bool IsTcpAck => string.Equals(Protocol, "TCP", StringComparison.OrdinalIgnoreCase) && (TcpFlags & 0x10) != 0;
    public bool IsTcpFin => string.Equals(Protocol, "TCP", StringComparison.OrdinalIgnoreCase) && (TcpFlags & 0x01) != 0;
    public bool IsTcpRst => string.Equals(Protocol, "TCP", StringComparison.OrdinalIgnoreCase) && (TcpFlags & 0x04) != 0;
    public bool IsTcpConnectionStart => IsTcpSyn && !IsTcpAck;
    public string TcpFlagsText
    {
        get
        {
            if (!string.Equals(Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) return "";
            var flags = new List<string>(6);
            if ((TcpFlags & 0x02) != 0) flags.Add("SYN");
            if ((TcpFlags & 0x10) != 0) flags.Add("ACK");
            if ((TcpFlags & 0x01) != 0) flags.Add("FIN");
            if ((TcpFlags & 0x04) != 0) flags.Add("RST");
            if ((TcpFlags & 0x08) != 0) flags.Add("PSH");
            if ((TcpFlags & 0x20) != 0) flags.Add("URG");
            return string.Join("|", flags);
        }
    }

    public string ServiceText
    {
        get
        {
            if (DestinationPort.HasValue) return $"{Protocol}/{DestinationPort.Value}";
            if (SourcePort.HasValue) return $"{Protocol}/{SourcePort.Value}";
            return Protocol;
        }
    }
}

public sealed class LiveTrafficNodeStat
{
    public string IpAddress { get; init; } = "";
    public double RxBytesPerSecond { get; init; }
    public double TxBytesPerSecond { get; init; }
    public double RxPacketsPerSecond { get; init; }
    public double TxPacketsPerSecond { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public string LastProtocol { get; init; } = "";
    public int? LastPort { get; init; }

    public double TotalBytesPerSecond => RxBytesPerSecond + TxBytesPerSecond;
    public double TotalPacketsPerSecond => RxPacketsPerSecond + TxPacketsPerSecond;
    public bool IsActive => TotalPacketsPerSecond > 0.01 || (DateTime.UtcNow - LastSeenUtc) < TimeSpan.FromSeconds(1.5);
    public string RateText => FormatRate(TotalBytesPerSecond);

    private static string FormatRate(double bytesPerSecond)
    {
        if (bytesPerSecond >= 1024 * 1024) return $"{bytesPerSecond / (1024 * 1024):0.0} MB/s";
        if (bytesPerSecond >= 1024) return $"{bytesPerSecond / 1024:0.0} KB/s";
        return $"{bytesPerSecond:0} B/s";
    }
}

public sealed class LiveTrafficFlow
{
    public string SourceIp { get; init; } = "";
    public string DestinationIp { get; init; } = "";
    public string Protocol { get; init; } = "IP";
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public double BytesPerSecond { get; init; }
    public double PacketsPerSecond { get; init; }
    public DateTime LastSeenUtc { get; init; }

    public string ServiceText => DestinationPort.HasValue ? $"{Protocol}/{DestinationPort.Value}" : Protocol;
}

public sealed class TrafficSnapshot
{
    public static TrafficSnapshot Empty { get; } = new();

    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    public IReadOnlyDictionary<string, LiveTrafficNodeStat> Nodes { get; init; } = new Dictionary<string, LiveTrafficNodeStat>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<LiveTrafficFlow> Flows { get; init; } = Array.Empty<LiveTrafficFlow>();
    public long TotalCapturedPackets { get; init; }
    public long TotalCapturedBytes { get; init; }
    public double CurrentPacketsPerSecond { get; init; }
    public double CurrentBytesPerSecond { get; init; }

    public string CurrentRateText
    {
        get
        {
            if (CurrentBytesPerSecond >= 1024 * 1024) return $"{CurrentBytesPerSecond / (1024 * 1024):0.0} MB/s";
            if (CurrentBytesPerSecond >= 1024) return $"{CurrentBytesPerSecond / 1024:0.0} KB/s";
            return $"{CurrentBytesPerSecond:0} B/s";
        }
    }
}
