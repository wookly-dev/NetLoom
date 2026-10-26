namespace NetLoom.App.Models;

public sealed class TopologyExternalNodeDecision
{
    public ExternalObservationNodeRecord Node { get; init; } = new();
    public int Score { get; init; }
    public bool ForceVisible { get; init; }
    public int InternalPeerCount { get; init; }
    public string PrimaryPeerIp { get; init; } = "";
    public string Reason { get; init; } = "";
}

public sealed class TopologySignificanceSnapshot
{
    public static TopologySignificanceSnapshot Empty { get; } = new();

    public IReadOnlyList<TopologyExternalNodeDecision> ExternalNodes { get; init; } = Array.Empty<TopologyExternalNodeDecision>();
    public IReadOnlyList<ExternalObservationFlowRecord> ExternalFlows { get; init; } = Array.Empty<ExternalObservationFlowRecord>();
    public int ObservedNodeCount { get; init; }
    public int RenderedNodeCount { get; init; }
    public int SuppressedNodeCount { get; init; }
    public int ObservedFlowCount { get; init; }
    public int RenderedFlowCount { get; init; }
    public int SuppressedFlowCount { get; init; }
    public bool SensorHostConnectionsExcluded { get; init; }
    public int SensorHostSuppressedNodeCount { get; init; }
    public int SensorHostSuppressedFlowCount { get; init; }
    public string ServiceSummaryText { get; init; } = "";
    public string Signature { get; init; } = "";

    public bool HasRenderedExternal => RenderedNodeCount > 0;
    public string SummaryText
    {
        get
        {
            if (ObservedNodeCount <= 0) return "관측 외부 노드 없음";
            string baseText = $"중요 연결 {RenderedNodeCount:N0} / 관측 {ObservedNodeCount:N0} · 숨김 {SuppressedNodeCount:N0}";
            if (!SensorHostConnectionsExcluded) return baseText;
            return $"{baseText} · 실행 PC 연결 제외 {SensorHostSuppressedFlowCount:N0} Flow";
        }
    }
}
