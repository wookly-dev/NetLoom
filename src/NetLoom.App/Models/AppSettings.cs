namespace NetLoom.App.Models;

public sealed class AppSettings
{
    public bool ResolveDns { get; set; } = true;
    public bool ResolveMac { get; set; } = true;
    public bool ShowOfflineInList { get; set; } = true;
    public bool AutoSwitchToMatrix { get; set; } = false;
    public bool LiveTopologyRefresh { get; set; } = true;
    public bool LightTopologyOutput { get; set; } = true;
    public bool AuditSmbShares { get; set; } = true;
    public bool TestGuestShareAccess { get; set; } = true;
    public bool ProbeDeviceIdentity { get; set; } = true;
    public bool QueryIppPrinterInfo { get; set; } = true;
    public bool QuerySnmpDeviceInfo { get; set; } = false;
    public string SnmpCommunity { get; set; } = "public";
    public bool DiscoverNestedNetworks { get; set; } = true;
    public PacketCaptureScopeMode PacketCaptureScope { get; set; } = PacketCaptureScopeMode.LocalHost;
    public bool ShowLocalExternalTopology { get; set; } = false;
    public bool ShowLowSignificanceExternalTopology { get; set; } = false;
    public bool ExcludeSensorHostTopologyConnections { get; set; } = true;
    public bool SensorHostTopologyExclusionDefaultV073Applied { get; set; } = true;

    public AppSettings Clone() => new()
    {
        ResolveDns = ResolveDns,
        ResolveMac = ResolveMac,
        ShowOfflineInList = ShowOfflineInList,
        AutoSwitchToMatrix = AutoSwitchToMatrix,
        LiveTopologyRefresh = LiveTopologyRefresh,
        LightTopologyOutput = LightTopologyOutput,
        AuditSmbShares = AuditSmbShares,
        TestGuestShareAccess = TestGuestShareAccess,
        ProbeDeviceIdentity = ProbeDeviceIdentity,
        QueryIppPrinterInfo = QueryIppPrinterInfo,
        QuerySnmpDeviceInfo = QuerySnmpDeviceInfo,
        SnmpCommunity = SnmpCommunity,
        DiscoverNestedNetworks = DiscoverNestedNetworks,
        PacketCaptureScope = PacketCaptureScope,
        ShowLocalExternalTopology = ShowLocalExternalTopology,
        ShowLowSignificanceExternalTopology = ShowLowSignificanceExternalTopology,
        ExcludeSensorHostTopologyConnections = ExcludeSensorHostTopologyConnections,
        SensorHostTopologyExclusionDefaultV073Applied = SensorHostTopologyExclusionDefaultV073Applied
    };
}
