namespace NetLoom.App.Models;

public sealed class PacketSecurityTag
{
    public static PacketSecurityTag None { get; } = new();

    public bool IsExternal { get; init; }
    public bool IsSuspicious { get; init; }
    public bool IsBeaconCandidate { get; init; }
    public bool IsBaselineAnomaly { get; init; }
    public bool IsLateralMovementCandidate { get; init; }
    public bool IsDnsAnomaly { get; init; }
    public bool IsPolicyException { get; init; }
    public string RiskLevel { get; init; } = "NORMAL";
    public string Reason { get; init; } = "";
}

public sealed class SecurityNodeAssessment
{
    public string IpAddress { get; init; } = "";
    public int RiskScore { get; init; }
    public string RiskLevel { get; init; } = "NORMAL";
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public int ExternalPeerCount { get; init; }
    public int RecentNewExternalCount { get; init; }
    public int FanOutExternalCount { get; init; }
    public int LongLivedFlowCount { get; init; }
    public int SuspiciousExternalPortCount { get; init; }
    public int HostSweepTargetCount { get; init; }
    public int PortSweepPortCount { get; init; }
    public int ExternalConnectionStarts5m { get; init; }
    public long ExternalBytes5m { get; init; }
    public long OutboundExternalBytes5m { get; init; }
    public long InboundExternalBytes5m { get; init; }
    public double UploadRatioPercent { get; init; }
    public int LateralMovementTargetCount { get; init; }
    public int DnsQueryCount5m { get; init; }
    public int DnsUniqueQueryCount5m { get; init; }
    public int DnsNxDomainCount5m { get; init; }
    public double DnsNxDomainRatioPercent { get; init; }
    public int DnsLongQueryCount5m { get; init; }
    public int DnsMaxQueryLength { get; init; }
    public int DnsAnomalyScore { get; init; }
    public bool PolicyTrustedInternal { get; init; }
    public int PolicyAllowedExternalCount { get; init; }
    public int UnapprovedExternalFanOutCount { get; init; }
    public int ExternalIntelWatchCount { get; init; }
    public int ExternalIntelSuspiciousCount { get; init; }
    public int BeaconCandidateCount { get; init; }
    public string BeaconExternalIp { get; init; } = "";
    public int? BeaconDestinationPort { get; init; }
    public double BeaconIntervalSeconds { get; init; }
    public double BeaconJitterPercent { get; init; }
    public int BeaconConfidenceScore { get; init; }
    public bool BaselineReady { get; init; }
    public int BaselineSampleCount { get; init; }
    public string BaselineScopeText { get; init; } = "학습 중";
    public int BaselineAnomalyScore { get; init; }
    public IReadOnlyList<string> BaselineReasons { get; init; } = Array.Empty<string>();
    public long ExternalPackets { get; init; }
    public long ExternalBytes { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    public bool IsSuspicious => RiskScore >= 25;
    public string ExternalBytesText => TrafficAuditFlowRecord.FormatBytes(ExternalBytes);
    public string LastSeenText => LastSeenUtc == default ? "-" : LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
    public string BaselineText => !BaselineReady
        ? $"LEARNING · {BaselineSampleCount:N0} samples"
        : BaselineAnomalyScore >= 55 ? $"ANOMALY {BaselineAnomalyScore}/100 · {BaselineScopeText}"
        : BaselineAnomalyScore >= 30 ? $"WATCH {BaselineAnomalyScore}/100 · {BaselineScopeText}"
        : $"NORMAL · {BaselineScopeText}";
    public string BeaconText => BeaconCandidateCount <= 0
        ? "없음"
        : $"{BeaconExternalIp}:{BeaconDestinationPort?.ToString() ?? "-"} · {BeaconIntervalSeconds:0.0}s · jitter {BeaconJitterPercent:0.0}%";
    public string UploadRatioText => ExternalBytes5m <= 0 ? "-" : $"{UploadRatioPercent:0.0}%";
    public string DnsAnomalyText => DnsQueryCount5m <= 0
        ? "-"
        : DnsAnomalyScore >= 30
            ? $"WATCH {DnsAnomalyScore}/100 · NX {DnsNxDomainRatioPercent:0}% · long {DnsLongQueryCount5m}"
            : $"NORMAL · {DnsQueryCount5m} q/5m · NX {DnsNxDomainRatioPercent:0}%";
    public string PolicyText => PolicyTrustedInternal
        ? "TRUSTED INTERNAL"
        : PolicyAllowedExternalCount > 0 ? $"ALLOW {PolicyAllowedExternalCount} external" : "-";
}

public sealed class SecurityFlowAssessment
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
    public bool IsExternal { get; init; }
    public bool IsLongLived { get; init; }
    public bool IsSuspiciousPort { get; init; }
    public int RiskScore { get; init; }
    public string RiskLevel { get; init; } = "NORMAL";
    public string Reason { get; init; } = "";

    public string ServiceText => TrafficAuditFlowRecord.DescribeService(Protocol, DestinationPort ?? SourcePort);
    public string BytesText => TrafficAuditFlowRecord.FormatBytes(Bytes);
    public TimeSpan Duration => LastSeenUtc > FirstSeenUtc ? LastSeenUtc - FirstSeenUtc : TimeSpan.Zero;
    public string DurationText => Duration.TotalHours >= 1
        ? $"{(int)Duration.TotalHours}:{Duration.Minutes:00}:{Duration.Seconds:00}"
        : $"{Duration.Minutes:00}:{Duration.Seconds:00}";
}

public sealed class SecurityRelationshipFinding
{
    public string Severity { get; init; } = "INFO";
    public string Code { get; init; } = "";
    public string IpAddress { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public int Score { get; init; }
}

public sealed class SecurityRelationshipSnapshot
{
    public static SecurityRelationshipSnapshot Empty { get; } = new();

    public DateTime SessionStartedUtc { get; init; }
    public DateTime TimestampUtc { get; init; }
    public long TotalPackets { get; init; }
    public long TotalBytes { get; init; }
    public IReadOnlyList<SecurityNodeAssessment> Nodes { get; init; } = Array.Empty<SecurityNodeAssessment>();
    public IReadOnlyList<SecurityFlowAssessment> SuspiciousFlows { get; init; } = Array.Empty<SecurityFlowAssessment>();
    public IReadOnlyList<SecurityRelationshipFinding> Findings { get; init; } = Array.Empty<SecurityRelationshipFinding>();
    public IReadOnlyList<BeaconCandidate> BeaconCandidates { get; init; } = Array.Empty<BeaconCandidate>();

    public int HighCount => Nodes.Count(n => string.Equals(n.RiskLevel, "HIGH", StringComparison.OrdinalIgnoreCase));
    public int MediumCount => Nodes.Count(n => string.Equals(n.RiskLevel, "MEDIUM", StringComparison.OrdinalIgnoreCase));
    public int WatchCount => Nodes.Count(n => string.Equals(n.RiskLevel, "WATCH", StringComparison.OrdinalIgnoreCase));
    public int SuspiciousNodeCount => Nodes.Count(n => n.IsSuspicious);
    public int BaselineReadyCount => Nodes.Count(n => n.BaselineReady);
    public int BaselineAnomalyCount => Nodes.Count(n => n.BaselineReady && n.BaselineAnomalyScore >= 30);
    public int BeaconNodeCount => Nodes.Count(n => n.BeaconCandidateCount > 0);
    public int LateralMovementNodeCount => Nodes.Count(n => !n.PolicyTrustedInternal && n.LateralMovementTargetCount >= 4);
    public int DnsAnomalyNodeCount => Nodes.Count(n => n.DnsAnomalyScore >= 30);
    public int PolicyTrustedNodeCount => Nodes.Count(n => n.PolicyTrustedInternal);
    public int IntelSuspiciousNodeCount => Nodes.Count(n => n.ExternalIntelSuspiciousCount > 0);
    public bool HasData => TotalPackets > 0 || Nodes.Count > 0;

    public SecurityNodeAssessment? FindNode(string ip) => Nodes.FirstOrDefault(n => string.Equals(n.IpAddress, ip, StringComparison.OrdinalIgnoreCase));
}
