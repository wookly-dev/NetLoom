namespace NetLoom.App.Models;

public sealed class ScanOptions
{
    public bool ResolveDns { get; init; } = true;
    public bool ResolveMac { get; init; } = true;
    public bool AuditSmbShares { get; init; } = true;
    public bool TestGuestShareAccess { get; init; } = true;
    public bool ProbeDeviceIdentity { get; init; } = true;
    public bool QueryIppPrinterInfo { get; init; } = true;
    public bool QuerySnmpDeviceInfo { get; init; } = false;
    public string SnmpCommunity { get; init; } = "";
    public bool DiscoverNestedNetworks { get; init; } = true;
    public string GatewayAddress { get; init; } = "";
    public EngineTraceVerbosity TraceVerbosity { get; set; } = EngineTraceVerbosity.Detailed;
}
