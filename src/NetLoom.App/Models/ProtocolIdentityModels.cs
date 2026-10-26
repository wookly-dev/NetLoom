namespace NetLoom.App.Models;

public sealed class SnmpIpv4InterfaceInfo
{
    public string Address { get; init; } = "";
    public string Netmask { get; init; } = "";
    public string Cidr { get; init; } = "";
}

public sealed class SnmpRouteInfo
{
    public string Destination { get; init; } = "";
    public string Netmask { get; init; } = "";
    public string NextHop { get; init; } = "";
    public string Cidr { get; init; } = "";
}

public sealed class SnmpDeviceInfo
{
    public bool Attempted { get; init; }
    public bool Success { get; init; }
    public string Status { get; init; } = "미실행";
    public string Version { get; init; } = "SNMP v2c";
    public string SysName { get; init; } = "";
    public string SysDescr { get; init; } = "";
    public string SysObjectId { get; init; } = "";
    public string SysLocation { get; init; } = "";
    public string SysUptime { get; init; } = "";
    public string IpForwarding { get; init; } = "";
    public IReadOnlyList<SnmpIpv4InterfaceInfo> Ipv4Interfaces { get; init; } = Array.Empty<SnmpIpv4InterfaceInfo>();
    public IReadOnlyList<SnmpRouteInfo> Routes { get; init; } = Array.Empty<SnmpRouteInfo>();
    public bool NetworkTablesAttempted { get; init; }
    public string NetworkTablesStatus { get; init; } = "미실행";

    public string Summary
    {
        get
        {
            if (!Attempted) return "미실행";
            if (!Success) return Status;
            if (!string.IsNullOrWhiteSpace(SysDescr)) return SysDescr;
            if (!string.IsNullOrWhiteSpace(SysName)) return SysName;
            return "SNMP 응답 확인";
        }
    }
}

public sealed class IppPrinterInfo
{
    public bool Attempted { get; init; }
    public bool Success { get; init; }
    public string Status { get; init; } = "미실행";
    public string PrinterUri { get; init; } = "";
    public string PrinterName { get; init; } = "";
    public string MakeAndModel { get; init; } = "";
    public string PrinterInfo { get; init; } = "";
    public string Location { get; init; } = "";
    public string PrinterState { get; init; } = "";
    public string PrinterStateReasons { get; init; } = "";
    public string PrinterUuid { get; init; } = "";
    public bool? ColorSupported { get; init; }
    public string SidesSupported { get; init; } = "";

    public string Summary
    {
        get
        {
            if (!Attempted) return "미실행";
            if (!Success) return Status;
            if (!string.IsNullOrWhiteSpace(MakeAndModel)) return MakeAndModel;
            if (!string.IsNullOrWhiteSpace(PrinterName)) return PrinterName;
            return "IPP 프린터 응답 확인";
        }
    }
}
