namespace NetLoom.App.Models;

public sealed class SecurityTimelineEntry
{
    public DateTime TimestampUtc { get; init; }
    public SecurityRelationshipSnapshot Snapshot { get; init; } = SecurityRelationshipSnapshot.Empty;
    public int HighCount => Snapshot.HighCount;
    public int MediumCount => Snapshot.MediumCount;
    public int WatchCount => Snapshot.WatchCount;
    public int DnsAnomalyCount => Snapshot.DnsAnomalyNodeCount;
    public int BeaconCount => Snapshot.BeaconNodeCount;
    public int LateralCount => Snapshot.LateralMovementNodeCount;
    public int BaselineAnomalyCount => Snapshot.BaselineAnomalyCount;
    public string TimeText => TimestampUtc.ToLocalTime().ToString("HH:mm:ss");
    public string TopRiskText => string.Join(" · ", Snapshot.Nodes.Where(n => n.RiskScore >= 25).OrderByDescending(n => n.RiskScore).Take(3).Select(n => $"{n.IpAddress} {n.RiskLevel}/{n.RiskScore}"));
}
