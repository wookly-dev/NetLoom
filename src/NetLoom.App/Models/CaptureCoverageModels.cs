namespace NetLoom.App.Models;

public enum PacketCaptureScopeMode
{
    LocalHost = 0,
    SpanTap = 1
}

public sealed class CaptureCoverageSnapshot
{
    public static CaptureCoverageSnapshot Empty { get; } = new();

    public PacketCaptureScopeMode Mode { get; init; } = PacketCaptureScopeMode.LocalHost;
    public bool IsRunning { get; init; }
    public string AdapterAddress { get; init; } = "";
    public long TotalPackets { get; init; }
    public long LocalEndpointPackets { get; init; }
    public long TransitPackets { get; init; }
    public long TransitExternalPackets { get; init; }
    public int TransitInternalHostCount { get; init; }
    public DateTime LastTransitSeenUtc { get; init; }
    public bool AllowLocalExternalTopology { get; init; }

    public bool IsSpanVerified =>
        Mode == PacketCaptureScopeMode.SpanTap &&
        TransitPackets >= 5 &&
        (TransitExternalPackets >= 3 || TransitInternalHostCount >= 2);

    public bool CanRenderObservedExternalTopology =>
        Mode == PacketCaptureScopeMode.SpanTap ? IsSpanVerified : AllowLocalExternalTopology;

    public string ModeText => Mode == PacketCaptureScopeMode.SpanTap ? "SPAN / TAP" : "LOCAL HOST";

    public string CoverageStateText
    {
        get
        {
            if (Mode == PacketCaptureScopeMode.LocalHost)
                return AllowLocalExternalTopology
                    ? "로컬 호스트 관측 · 외부 노드 제한 표시"
                    : "로컬 호스트 관측 · 외부 관계도 상세 숨김";

            if (IsSpanVerified)
                return $"SPAN 확인 · Transit {TransitPackets:N0} pkt · 외부 {TransitExternalPackets:N0} · 내부 호스트 {TransitInternalHostCount:N0}";

            return IsRunning
                ? $"SPAN 대기 · Transit {TransitPackets:N0} pkt · 미러 트래픽 미확인"
                : "SPAN 설정 · 미러 트래픽 미확인";
        }
    }

    public string TopologyPolicyText => CanRenderObservedExternalTopology
        ? Mode == PacketCaptureScopeMode.SpanTap
            ? "미러링 Transit이 확인되어 관찰 External/Public 노드를 관계도에 표시합니다."
            : "LOCAL 모드 외부 상세 표시 옵션이 켜져 있어 로컬 PC의 관찰 External/Public 노드를 제한적으로 표시합니다."
        : Mode == PacketCaptureScopeMode.SpanTap
            ? "SPAN/TAP Transit이 확인되기 전까지 관찰 External/Public 노드를 관계도에서 숨깁니다. 명시적으로 스캔한 공인 IP는 유지됩니다."
            : "LOCAL HOST 모드에서는 다른 사내 장비의 외부 Unicast를 관측한다고 볼 수 없으므로 관찰 External/Public 노드를 관계도에서 숨깁니다. 명시적으로 스캔한 공인 IP는 유지됩니다.";
}
