namespace NetLoom.App.Models;

public sealed class ScanResult
{
    public bool IsOnline { get; init; }
    public string Status => IsOnline ? "ONLINE" : "OFFLINE";
    public string IpAddress { get; init; } = "";
    public string HostName { get; init; } = "";
    public string MacAddress { get; init; } = "";
    public long? RoundTripMs { get; init; }
    public string RoundTripDisplay => RoundTripMs.HasValue ? $"{RoundTripMs.Value} ms" : "-";
    public IReadOnlyList<int> OpenPortNumbers { get; init; } = Array.Empty<int>();
    public string OpenPorts => OpenPortNumbers.Count == 0 ? "" : string.Join(", ", OpenPortNumbers);
    public DeviceType DeviceType { get; init; } = DeviceType.Unknown;
    public int ClassificationConfidence { get; init; }
    public IReadOnlyList<string> ClassificationEvidence { get; init; } = Array.Empty<string>();
    public string DeviceLabel => DeviceType.ToDisplayName();
    public string ClassificationDisplay => ClassificationConfidence > 0 ? $"{DeviceLabel} · {ClassificationConfidence}%" : DeviceLabel;
    public bool IsGateway { get; init; }
    public SmbShareAuditResult ShareAudit { get; init; } = new();
    public IppPrinterInfo IppInfo { get; init; } = new();
    public SnmpDeviceInfo SnmpInfo { get; init; } = new();
    public string ShareAuditSummary => ShareAudit.Summary;
    public string GuestShareNames => ShareAudit.GuestAccessibleShares.Count == 0 ? "" : string.Join(", ", ShareAudit.GuestAccessibleShares);
    public string ProtocolIdentitySummary
    {
        get
        {
            if (IppInfo.Success && !string.IsNullOrWhiteSpace(IppInfo.MakeAndModel)) return $"IPP · {IppInfo.MakeAndModel}";
            if (SnmpInfo.Success && !string.IsNullOrWhiteSpace(SnmpInfo.SysDescr)) return $"SNMP · {SnmpInfo.SysDescr}";
            if (IppInfo.Success) return $"IPP · {(string.IsNullOrWhiteSpace(IppInfo.PrinterName) ? "확인" : IppInfo.PrinterName)}";
            if (SnmpInfo.Success) return $"SNMP · {(string.IsNullOrWhiteSpace(SnmpInfo.SysName) ? "확인" : SnmpInfo.SysName)}";
            return "-";
        }
    }
    public bool HasProtocolIdentity => IppInfo.Success || SnmpInfo.Success;
    public bool HasGuestShareExposure => ShareAudit.HasGuestAccessibleShare;

    // Assigned by the UI after the scanner returns the host result.
    // It lets list, matrix, detail dialog and reports keep multiple audit ranges visually separated.
    public string AuditGroupLabel { get; set; } = "대역 A";
    public string AuditGroupExpression { get; set; } = "";
    public string AuditGatewayAddress { get; set; } = "";

    public string DisplayHostName => string.IsNullOrWhiteSpace(HostName) ? "-" : HostName;
    public string DisplayMacAddress => string.IsNullOrWhiteSpace(MacAddress) ? "-" : MacAddress;
    public string DisplayOpenPorts => string.IsNullOrWhiteSpace(OpenPorts) ? "-" : OpenPorts;
    public uint IpSortKey
    {
        get
        {
            if (!System.Net.IPAddress.TryParse(IpAddress, out var ip)) return uint.MaxValue;
            var b = ip.GetAddressBytes();
            if (b.Length != 4) return uint.MaxValue;
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }
    }
    public string ToolTipText => $"{IpAddress}  ·  {AuditGroupLabel}\n장치: {ClassificationDisplay}\n호스트: {DisplayHostName}\n응답: {RoundTripDisplay}\n포트: {DisplayOpenPorts}\n식별: {ProtocolIdentitySummary}\n공유 감사: {ShareAuditSummary}\n클릭하면 장비 상세를 엽니다.";
}
