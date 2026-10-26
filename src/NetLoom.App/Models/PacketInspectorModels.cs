namespace NetLoom.App.Models;

public sealed class PacketInspectorSettings
{
    public string Keywords { get; set; } = "password\npasswd\ntoken\napi_key\napikey\nsecret\nauthorization\ncookie\nsession\ncredential";
    public bool InspectPlaintextPreview { get; set; } = true;
    public int MaxPreviewBytes { get; set; } = 384;
}

public sealed class PacketInspectorRow
{
    public DateTime TimestampUtc { get; init; }
    public string TimeText => TimestampUtc.ToLocalTime().ToString("HH:mm:ss.fff");
    public string Direction { get; init; } = "";
    public string Protocol { get; init; } = "IP";
    public string SourceIp { get; init; } = "";
    public int? SourcePort { get; init; }
    public string SourcePortText => SourcePort?.ToString() ?? "";
    public string DestinationIp { get; init; } = "";
    public int? DestinationPort { get; init; }
    public string DestinationPortText => DestinationPort?.ToString() ?? "";
    public string Service { get; init; } = "";
    public string Flags { get; init; } = "";
    public int Length { get; init; }
    public string LengthText => $"{Length:N0} B";
    public string Summary { get; init; } = "";
    public string KeywordHits { get; set; } = "";
    public string Preview { get; init; } = "";
    public string SearchText { get; init; } = "";
    public bool IsExternalTraffic { get; init; }
    public bool IsSecuritySuspicious { get; init; }
    public bool IsBeaconCandidate { get; init; }
    public bool IsBaselineAnomaly { get; init; }
    public bool IsLateralMovementCandidate { get; init; }
    public bool IsDnsAnomaly { get; init; }
    public bool IsPolicyException { get; init; }
    public string SecurityLevel { get; init; } = "NORMAL";
    public string SecurityReason { get; init; } = "";
    public bool IsTcpSyn { get; init; }
    public string SecurityText => IsSecuritySuspicious
        ? $"{SecurityLevel} · {SecurityReason}"
        : IsPolicyException ? "ALLOWLIST"
        : IsExternalTraffic ? "EXTERNAL" : "";
    public bool HasKeywordHit => !string.IsNullOrWhiteSpace(KeywordHits);
}
