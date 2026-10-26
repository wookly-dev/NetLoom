namespace NetLoom.App.Models;

public sealed class TopologyRootNetwork
{
    public string GroupLabel { get; init; } = "";
    public string Expression { get; init; } = "";
    public string GatewayAddress { get; init; } = "";
    public string InterfaceAddress { get; init; } = "";
    public string Source { get; init; } = "";
    public bool IsDirect { get; init; }

    public string DisplayName => string.IsNullOrWhiteSpace(GatewayAddress)
        ? $"{GroupLabel} · Gateway 미확인"
        : $"{GroupLabel} · GW {GatewayAddress}";
}
