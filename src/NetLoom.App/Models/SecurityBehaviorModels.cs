namespace NetLoom.App.Models;

/// <summary>
/// Compact behavior sample used for the persistent per-device baseline. Values are intentionally
/// metadata-only; no payload/body data is persisted by the baseline subsystem.
/// </summary>
public sealed class SecurityBehaviorSample
{
    public int ExternalFanOut5m { get; init; }
    public int ExternalConnectionStarts5m { get; init; }
    public long ExternalBytes5m { get; init; }
    public long OutboundExternalBytes5m { get; init; }
    public int InternalManagementTargets5m { get; init; }
}

public sealed class SecurityMetricStats
{
    public int Samples { get; set; }
    public double Mean { get; set; }
    public double M2 { get; set; }

    public double StandardDeviation => Samples > 1 ? Math.Sqrt(Math.Max(0, M2 / (Samples - 1))) : 0;

    public void Update(double value)
    {
        Samples++;
        double delta = value - Mean;
        Mean += delta / Samples;
        double delta2 = value - Mean;
        M2 += delta * delta2;
    }
}

public sealed class SecurityBaselineBucket
{
    public int Samples { get; set; }
    public SecurityMetricStats ExternalFanOut5m { get; set; } = new();
    public SecurityMetricStats ExternalConnectionStarts5m { get; set; } = new();
    public SecurityMetricStats ExternalBytes5m { get; set; } = new();
    public SecurityMetricStats OutboundExternalBytes5m { get; set; } = new();
    public SecurityMetricStats InternalManagementTargets5m { get; set; } = new();

    public void Update(SecurityBehaviorSample sample)
    {
        Samples++;
        ExternalFanOut5m.Update(sample.ExternalFanOut5m);
        ExternalConnectionStarts5m.Update(sample.ExternalConnectionStarts5m);
        ExternalBytes5m.Update(sample.ExternalBytes5m);
        OutboundExternalBytes5m.Update(sample.OutboundExternalBytes5m);
        InternalManagementTargets5m.Update(sample.InternalManagementTargets5m);
    }
}

public sealed class SecurityDeviceBaselineProfile
{
    public string IpAddress { get; set; } = "";
    public DateTime FirstLearnedUtc { get; set; }
    public DateTime LastLearnedUtc { get; set; }
    public SecurityBaselineBucket Overall { get; set; } = new();
    public Dictionary<int, SecurityBaselineBucket> Hourly { get; set; } = new();
}

public sealed class SecurityBehaviorBaselineDocument
{
    public int SchemaVersion { get; set; } = 1;
    public DateTime UpdatedUtc { get; set; }
    public Dictionary<string, SecurityDeviceBaselineProfile> Devices { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class SecurityBaselineEvaluation
{
    public bool IsReady { get; init; }
    public int SampleCount { get; init; }
    public string ScopeText { get; init; } = "학습 중";
    public int AnomalyScore { get; init; }
    public double FanOutZ { get; init; }
    public double ConnectionStartsZ { get; init; }
    public double ExternalBytesZ { get; init; }
    public double OutboundBytesZ { get; init; }
    public double ManagementTargetsZ { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();

    public string StatusText => !IsReady
        ? $"LEARNING · {SampleCount:N0} samples"
        : AnomalyScore >= 55 ? $"ANOMALY {AnomalyScore}/100 · {ScopeText}"
        : AnomalyScore >= 30 ? $"WATCH {AnomalyScore}/100 · {ScopeText}"
        : $"NORMAL · {ScopeText}";
}

public sealed class BeaconCandidate
{
    public string InternalIp { get; init; } = "";
    public string ExternalIp { get; init; } = "";
    public string Protocol { get; init; } = "TCP";
    public int? DestinationPort { get; init; }
    public int ObservationCount { get; init; }
    public double IntervalSeconds { get; init; }
    public double JitterPercent { get; init; }
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public int ConfidenceScore { get; init; }

    public string ServiceText => TrafficAuditFlowRecord.DescribeService(Protocol, DestinationPort);
    public string IntervalText => IntervalSeconds >= 60
        ? $"{IntervalSeconds / 60.0:0.0}분"
        : $"{IntervalSeconds:0.0}초";
}
