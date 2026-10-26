using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class DeviceDetailWindow : Window
{
    private readonly ScanResult _result;

    public DeviceDetailWindow(ScanResult result, SecurityNodeAssessment? security = null)
    {
        InitializeComponent();
        _result = result;

        var openPorts = result.OpenPortNumbers ?? Array.Empty<int>();
        var shareAudit = result.ShareAudit ?? new SmbShareAuditResult();
        var ippInfo = result.IppInfo ?? new IppPrinterInfo();
        var snmpInfo = result.SnmpInfo ?? new SnmpDeviceInfo();
        var classificationEvidence = result.ClassificationEvidence ?? Array.Empty<string>();

        DeviceGlyph.DeviceType = result.DeviceType;
        DeviceTitleText.Text = $"{result.DeviceLabel} · {result.IpAddress}";
        DeviceSubtitleText.Text = string.IsNullOrWhiteSpace(result.HostName) ? "호스트명 미확인" : result.HostName;
        StatusBadgeText.Text = result.Status;
        GroupText.Text = result.AuditGroupLabel;
        IpText.Text = result.IpAddress;
        HostText.Text = result.DisplayHostName;
        MacText.Text = result.DisplayMacAddress;
        RttText.Text = result.RoundTripDisplay;
        PortsText.Text = result.DisplayOpenPorts;
        GroupExpressionText.Text = string.IsNullOrWhiteSpace(result.AuditGroupExpression) ? "-" : result.AuditGroupExpression;
        SmbSummaryText.Text = result.ShareAuditSummary;
        ClassificationConfidenceText.Text = result.ClassificationConfidence > 0
            ? $"{result.DeviceLabel} · {result.ClassificationConfidence}%"
            : $"{result.DeviceLabel} · 미확정";
        ClassificationEvidenceItems.ItemsSource = classificationEvidence.Count > 0
            ? classificationEvidence
            : new[] { "식별 가능한 고유 신호가 부족합니다. 필요한 감사 포트를 추가한 뒤 다시 스캔하세요." };

        ApplySecurityProfile(security);

        ProtocolIdentityBadgeText.Text = result.HasProtocolIdentity ? "PROTOCOL VERIFIED" : "HEURISTIC";
        ProtocolIdentityBadgeText.Foreground = new System.Windows.Media.SolidColorBrush(
            result.HasProtocolIdentity
                ? System.Windows.Media.Color.FromRgb(98, 217, 166)
                : System.Windows.Media.Color.FromRgb(160, 160, 160));

        IppStatusText.Text = ippInfo.Attempted ? ippInfo.Status : "미실행";
        IppModelText.Text = ippInfo.Success
            ? (!string.IsNullOrWhiteSpace(ippInfo.MakeAndModel) ? ippInfo.MakeAndModel : ippInfo.PrinterName)
            : "-";
        var ippDetails = new List<string>();
        if (!string.IsNullOrWhiteSpace(ippInfo.PrinterName)) ippDetails.Add($"Name: {ippInfo.PrinterName}");
        if (!string.IsNullOrWhiteSpace(ippInfo.Location)) ippDetails.Add($"Location: {ippInfo.Location}");
        if (!string.IsNullOrWhiteSpace(ippInfo.PrinterState)) ippDetails.Add($"State: {ippInfo.PrinterState}");
        if (ippInfo.ColorSupported.HasValue) ippDetails.Add($"Color: {(ippInfo.ColorSupported.Value ? "Yes" : "No")}");
        if (!string.IsNullOrWhiteSpace(ippInfo.SidesSupported)) ippDetails.Add($"Sides: {ippInfo.SidesSupported}");
        IppDetailText.Text = ippDetails.Count > 0 ? string.Join(" · ", ippDetails) : "IPP 속성 없음";

        SnmpStatusText.Text = snmpInfo.Attempted ? snmpInfo.Status : "미실행";
        SnmpNameText.Text = snmpInfo.Success
            ? (!string.IsNullOrWhiteSpace(snmpInfo.SysName) ? snmpInfo.SysName : "SNMP 응답 장비")
            : "-";
        var snmpDetails = new List<string>();
        if (!string.IsNullOrWhiteSpace(snmpInfo.SysDescr)) snmpDetails.Add(snmpInfo.SysDescr);
        if (!string.IsNullOrWhiteSpace(snmpInfo.SysLocation)) snmpDetails.Add($"Location: {snmpInfo.SysLocation}");
        if (!string.IsNullOrWhiteSpace(snmpInfo.SysObjectId)) snmpDetails.Add($"OID: {snmpInfo.SysObjectId}");
        if (!string.IsNullOrWhiteSpace(snmpInfo.SysUptime)) snmpDetails.Add($"Uptime: {snmpInfo.SysUptime}");
        if (snmpInfo.IpForwarding == "1") snmpDetails.Add("IPv4 Forwarding: ON");
        if (snmpInfo.NetworkTablesAttempted) snmpDetails.Add(snmpInfo.NetworkTablesStatus);
        if (snmpInfo.Ipv4Interfaces.Count > 0)
            snmpDetails.Add($"Interfaces: {string.Join(", ", snmpInfo.Ipv4Interfaces.Select(i => i.Cidr).Distinct(StringComparer.OrdinalIgnoreCase).Take(6))}");
        if (snmpInfo.Routes.Count > 0)
            snmpDetails.Add($"Routes: {string.Join(", ", snmpInfo.Routes.Where(r => r.Cidr != "0.0.0.0/0").Select(r => r.Cidr).Distinct(StringComparer.OrdinalIgnoreCase).Take(6))}");
        SnmpDetailText.Text = snmpDetails.Count > 0 ? string.Join(" · ", snmpDetails) : "SNMP 시스템 정보 없음";

        if (!result.IsOnline)
        {
            StatusBadge.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(30, 30, 30));
            StatusBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(65, 65, 65));
            StatusBadgeText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(145, 145, 145));
        }

        var guestShares = shareAudit.GuestAccessibleShares ?? Array.Empty<string>();
        var enumeratedShares = shareAudit.EnumeratedShares ?? Array.Empty<string>();
        var guest = guestShares.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var shares = enumeratedShares
            .Concat(guestShares)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.CurrentCultureIgnoreCase)
            .Select(name => new ShareItem
            {
                Name = name,
                Path = $@"\\{result.IpAddress}\{name}",
                IsGuestAccessible = guest.Contains(name)
            })
            .ToArray();

        ShareItemsControl.ItemsSource = shares;
        NoSharesText.Visibility = shares.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        GuestWarningBorder.Visibility = result.HasGuestShareExposure ? Visibility.Visible : Visibility.Collapsed;
        OpenHostButton.IsEnabled = shareAudit.SmbDetected || openPorts.Contains(445) || openPorts.Contains(139);
        OpenWebButton.IsEnabled = openPorts.Contains(80) || openPorts.Contains(443);
        OpenRdpButton.IsEnabled = openPorts.Contains(3389);
    }

    private void ApplySecurityProfile(SecurityNodeAssessment? security)
    {
        if (security is null)
        {
            SecurityRiskText.Text = "ANALYSIS WAIT";
            SecurityBaselineText.Text = "학습/관찰 데이터 없음";
            SecurityExternalText.Text = "관찰 데이터 없음";
            SecurityBeaconText.Text = "관찰 데이터 없음";
            SecurityLateralText.Text = "관찰 데이터 없음";
            SecurityDnsText.Text = "관찰 데이터 없음";
            SecurityPolicyText.Text = "정책/인텔리전스 일치 없음";
            SecurityReasonItems.ItemsSource = new[] { "실시간 통신 캡처 또는 패킷 트레이서 관찰 후 보안 프로파일이 계산됩니다." };
            return;
        }

        SecurityRiskText.Text = $"{security.RiskLevel} {security.RiskScore}/100";
        var color = security.RiskLevel switch
        {
            "HIGH" => System.Windows.Media.Color.FromRgb(255, 112, 96),
            "MEDIUM" => System.Windows.Media.Color.FromRgb(244, 183, 72),
            "WATCH" => System.Windows.Media.Color.FromRgb(250, 216, 59),
            _ => System.Windows.Media.Color.FromRgb(98, 217, 166)
        };
        SecurityRiskText.Foreground = new System.Windows.Media.SolidColorBrush(color);
        SecurityRiskBadge.BorderBrush = new System.Windows.Media.SolidColorBrush(color);
        SecurityBaselineText.Text = security.BaselineText;
        SecurityExternalText.Text = $"peer {security.ExternalPeerCount:N0} · SYN {security.ExternalConnectionStarts5m:N0}/5m · {TrafficAuditFlowRecord.FormatBytes(security.ExternalBytes5m)} · 송신 {security.UploadRatioText}";
        SecurityBeaconText.Text = security.BeaconCandidateCount > 0
            ? $"{security.BeaconText} · confidence {security.BeaconConfidenceScore}/100"
            : "후보 없음";
        SecurityLateralText.Text = security.LateralMovementTargetCount > 0
            ? $"관리포트 대상 {security.LateralMovementTargetCount:N0}대/5m · Host sweep {security.HostSweepTargetCount:N0}대/60s"
            : $"후보 없음 · Host sweep {security.HostSweepTargetCount:N0}대/60s";
        SecurityDnsText.Text = security.DnsAnomalyText;
        SecurityPolicyText.Text = $"{security.PolicyText} · Intel S {security.ExternalIntelSuspiciousCount:N0} / W {security.ExternalIntelWatchCount:N0}";

        SecurityReasonItems.ItemsSource = security.Reasons.Count > 0
            ? security.Reasons.Take(5).ToArray()
            : new[] { "현재 누적 구간에서 WATCH 이상 행동 휴리스틱이 없습니다." };
    }

    private void OpenHost_Click(object sender, RoutedEventArgs e) => OpenShellPath($@"\\{_result.IpAddress}");

    private void OpenShare_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { CommandParameter: string path } && !string.IsNullOrWhiteSpace(path))
            OpenShellPath(path);
    }

    private void OpenWeb_Click(object sender, RoutedEventArgs e)
    {
        string scheme = (_result.OpenPortNumbers ?? Array.Empty<int>()).Contains(443) ? "https" : "http";
        OpenShellPath($"{scheme}://{_result.IpAddress}/");
    }

    private void OpenRdp_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("mstsc.exe", $"/v:{_result.IpAddress}") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"RDP 실행에 실패했습니다.\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static void OpenShellPath(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"열기에 실패했습니다.\n{path}\n\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private sealed class ShareItem
    {
        public string Name { get; init; } = "";
        public string Path { get; init; } = "";
        public bool IsGuestAccessible { get; init; }
    }
}
