namespace NetLoom.App.Models;

public sealed class AuditReportContext
{
    public DateTime ScanStartedAt { get; init; }
    public TimeSpan ScanDuration { get; init; }
    public string AdapterDisplay { get; init; } = "";
    public string TargetExpression { get; init; } = "";
    public string GatewayAddress { get; init; } = "";
    public IReadOnlyList<int> SelectedPorts { get; init; } = Array.Empty<int>();
    public WifiAuditResult? WifiAudit { get; init; }
    public IReadOnlyList<NestedNetworkInfo> NestedNetworks { get; init; } = Array.Empty<NestedNetworkInfo>();
    public TrafficSnapshot? TrafficSnapshot { get; init; }
    public TrafficAuditSessionSnapshot? TrafficAuditSession { get; init; }
    public SecurityRelationshipSnapshot? SecurityRelationship { get; init; }
    public ExternalObservationSnapshot? ExternalObservation { get; init; }
    public CaptureCoverageSnapshot? CaptureCoverage { get; init; }
    public bool IncludeLowSignificanceExternalTopology { get; init; }
    public bool ExcludeSensorHostTopologyConnections { get; init; }
}
