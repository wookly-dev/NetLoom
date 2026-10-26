namespace NetLoom.App.Models;

public sealed class TrafficAuditFlowRecord
{
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public string SourceIp { get; init; } = "";
    public string DestinationIp { get; init; } = "";
    public string Protocol { get; init; } = "IP";
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public long Packets { get; init; }
    public long Bytes { get; init; }
    public long ConnectionStarts { get; init; }
    public long ConnectionEnds { get; init; }

    public string FirstSeenText => FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss");
    public string LastSeenText => LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
    public string ServiceText => DescribeService(Protocol, DestinationPort ?? SourcePort);
    public string BytesText => FormatBytes(Bytes);

    public static string DescribeService(string protocol, int? port)
    {
        if (!port.HasValue) return protocol;
        string name = port.Value switch
        {
            20 or 21 => "FTP",
            22 => "SSH",
            23 => "TELNET",
            25 or 465 or 587 => "SMTP",
            53 => "DNS",
            67 or 68 => "DHCP",
            80 => "HTTP",
            110 or 995 => "POP3",
            123 => "NTP",
            135 => "RPC",
            137 or 138 or 139 => "NETBIOS",
            143 or 993 => "IMAP",
            161 or 162 => "SNMP",
            389 or 636 => "LDAP",
            443 => "HTTPS",
            445 => "SMB",
            515 => "LPD",
            548 => "AFP",
            631 => "IPP",
            873 => "RSYNC",
            1433 => "MSSQL",
            1521 => "ORACLE",
            1883 or 8883 => "MQTT",
            2049 => "NFS",
            3306 => "MYSQL",
            3389 => "RDP",
            5060 or 5061 => "SIP",
            5432 => "POSTGRESQL",
            5900 => "VNC",
            6379 => "REDIS",
            8080 or 8443 => "WEB",
            9100 => "RAW-PRINT",
            _ => ""
        };
        return string.IsNullOrEmpty(name) ? $"{protocol}/{port.Value}" : $"{protocol}/{port.Value} · {name}";
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes >= 1024L * 1024L * 1024L) return $"{bytes / (1024d * 1024d * 1024d):0.00} GB";
        if (bytes >= 1024L * 1024L) return $"{bytes / (1024d * 1024d):0.00} MB";
        if (bytes >= 1024L) return $"{bytes / 1024d:0.0} KB";
        return $"{bytes:N0} B";
    }
}

public sealed class TrafficAuditNodeRecord
{
    public string IpAddress { get; init; } = "";
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public long TxPackets { get; init; }
    public long RxPackets { get; init; }
    public long TxBytes { get; init; }
    public long RxBytes { get; init; }
    public long TotalPackets => TxPackets + RxPackets;
    public long TotalBytes => TxBytes + RxBytes;
    public string TotalBytesText => TrafficAuditFlowRecord.FormatBytes(TotalBytes);
}

public sealed class TrafficAuditSessionSnapshot
{
    public static TrafficAuditSessionSnapshot Empty { get; } = new();

    public string SessionId { get; init; } = "";
    public bool IsRecording { get; init; }
    public DateTime StartedAtUtc { get; init; }
    public DateTime? EndedAtUtc { get; init; }
    public string EndReason { get; init; } = "";
    public string AdapterAddress { get; init; } = "";
    public string AdapterDisplay { get; init; } = "";
    public long TotalPackets { get; init; }
    public long TotalBytes { get; init; }
    public int UniqueFlowCount { get; init; }
    public int UniqueNodeCount { get; init; }
    public IReadOnlyList<TrafficAuditFlowRecord> Flows { get; init; } = Array.Empty<TrafficAuditFlowRecord>();
    public IReadOnlyList<TrafficAuditNodeRecord> Nodes { get; init; } = Array.Empty<TrafficAuditNodeRecord>();
    public string SavedPath { get; init; } = "";

    public bool HasData => !string.IsNullOrWhiteSpace(SessionId) && (TotalPackets > 0 || UniqueFlowCount > 0);
    public DateTime EffectiveEndUtc => EndedAtUtc ?? DateTime.UtcNow;
    public TimeSpan Duration => StartedAtUtc == default ? TimeSpan.Zero : EffectiveEndUtc - StartedAtUtc;
    public string StartedText => StartedAtUtc == default ? "-" : StartedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string EndedText => IsRecording ? "기록 중" : EndedAtUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "-";
    public string DurationText => Duration.TotalHours >= 1 ? Duration.ToString(@"hh\:mm\:ss") : Duration.ToString(@"mm\:ss");
    public string TotalBytesText => TrafficAuditFlowRecord.FormatBytes(TotalBytes);
}
