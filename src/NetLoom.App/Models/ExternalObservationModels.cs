namespace NetLoom.App.Models;

public sealed class ExternalObservationNodeRecord
{
    public string IpAddress { get; init; } = "";
    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }
    public long Packets { get; init; }
    public long Bytes { get; init; }
    public string LastPeerIp { get; init; } = "";
    public string LastProtocol { get; init; } = "IP";
    public int? LastPort { get; init; }
    public string ObservedHost { get; init; } = "";
    public string ServiceGroup { get; init; } = "Unknown";
    public string Country { get; init; } = "";
    public string Asn { get; init; } = "";
    public string Provider { get; init; } = "";
    public string IntelligenceClassification { get; init; } = "UNKNOWN";

    public string LastSeenText => LastSeenUtc == default ? "-" : LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
    public string BytesText => TrafficAuditFlowRecord.FormatBytes(Bytes);
    public string ServiceText => TrafficAuditFlowRecord.DescribeService(LastProtocol, LastPort);
    public string IntelligenceText
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(ServiceGroup)) parts.Add(ServiceGroup);
            if (!string.IsNullOrWhiteSpace(ObservedHost)) parts.Add(ObservedHost);
            if (!string.IsNullOrWhiteSpace(Country)) parts.Add(Country);
            if (!string.IsNullOrWhiteSpace(Asn)) parts.Add(Asn);
            if (!string.IsNullOrWhiteSpace(Provider)) parts.Add(Provider);
            if (!string.IsNullOrWhiteSpace(IntelligenceClassification) && !string.Equals(IntelligenceClassification, "UNKNOWN", StringComparison.OrdinalIgnoreCase))
                parts.Add(IntelligenceClassification);
            return string.Join(" · ", parts.Distinct(StringComparer.OrdinalIgnoreCase));
        }
    }
}

public sealed class ExternalObservationFlowRecord
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

    public string ServiceText => TrafficAuditFlowRecord.DescribeService(Protocol, DestinationPort ?? SourcePort);
}

public sealed class ExternalObservationSnapshot
{
    public static ExternalObservationSnapshot Empty { get; } = new();

    // Changes when the external IP node set or node display metadata (service/intelligence) changes.
    // 3D can rebuild only when visual identity/grouping changes rather than on every packet.
    public long NodeSetVersion { get; init; }
    public IReadOnlyList<ExternalObservationNodeRecord> Nodes { get; init; } = Array.Empty<ExternalObservationNodeRecord>();
    public IReadOnlyList<ExternalObservationFlowRecord> Flows { get; init; } = Array.Empty<ExternalObservationFlowRecord>();

    public int Count => Nodes.Count;
    public bool HasData => Nodes.Count > 0;
}
