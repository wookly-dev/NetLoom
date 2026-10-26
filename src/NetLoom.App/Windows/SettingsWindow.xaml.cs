using System.Windows;
using System.Windows.Input;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class SettingsWindow : Window
{
    public AppSettings Settings { get; private set; }

    public SettingsWindow(AppSettings settings)
    {
        InitializeComponent();
        Settings = settings.Clone();

        ResolveDnsCheck.IsChecked = Settings.ResolveDns;
        ResolveMacCheck.IsChecked = Settings.ResolveMac;
        ShowOfflineCheck.IsChecked = Settings.ShowOfflineInList;
        AutoMatrixCheck.IsChecked = Settings.AutoSwitchToMatrix;
        LiveTopologyCheck.IsChecked = Settings.LiveTopologyRefresh;
        LightTopologyCheck.IsChecked = Settings.LightTopologyOutput;
        AuditSmbCheck.IsChecked = Settings.AuditSmbShares;
        GuestShareCheck.IsChecked = Settings.TestGuestShareAccess;
        IdentityProbeCheck.IsChecked = Settings.ProbeDeviceIdentity;
        IppQueryCheck.IsChecked = Settings.QueryIppPrinterInfo;
        SnmpQueryCheck.IsChecked = Settings.QuerySnmpDeviceInfo;
        NestedDiscoveryCheck.IsChecked = Settings.DiscoverNestedNetworks;
        SnmpCommunityBox.Password = Settings.SnmpCommunity ?? "";
        CaptureScopeCombo.SelectedIndex = Settings.PacketCaptureScope == PacketCaptureScopeMode.SpanTap ? 1 : 0;
        ShowLocalExternalTopologyCheck.IsChecked = Settings.ShowLocalExternalTopology;
        ShowLowSignificanceExternalTopologyCheck.IsChecked = Settings.ShowLowSignificanceExternalTopology;
        ExcludeSensorHostTopologyConnectionsCheck.IsChecked = Settings.ExcludeSensorHostTopologyConnections;
        UpdateGuestShareState();
        UpdateSnmpState();
        UpdateCaptureScopeState();
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        Settings.ResolveDns = ResolveDnsCheck.IsChecked == true;
        Settings.ResolveMac = ResolveMacCheck.IsChecked == true;
        Settings.ShowOfflineInList = ShowOfflineCheck.IsChecked == true;
        Settings.AutoSwitchToMatrix = AutoMatrixCheck.IsChecked == true;
        Settings.LiveTopologyRefresh = LiveTopologyCheck.IsChecked == true;
        Settings.LightTopologyOutput = LightTopologyCheck.IsChecked == true;
        Settings.AuditSmbShares = AuditSmbCheck.IsChecked == true;
        Settings.TestGuestShareAccess = Settings.AuditSmbShares && GuestShareCheck.IsChecked == true;
        Settings.ProbeDeviceIdentity = IdentityProbeCheck.IsChecked == true;
        Settings.QueryIppPrinterInfo = IppQueryCheck.IsChecked == true;
        Settings.QuerySnmpDeviceInfo = SnmpQueryCheck.IsChecked == true;
        Settings.SnmpCommunity = SnmpCommunityBox.Password.Trim();
        Settings.DiscoverNestedNetworks = Settings.QuerySnmpDeviceInfo && NestedDiscoveryCheck.IsChecked == true;
        Settings.PacketCaptureScope = GetSelectedCaptureScope();
        Settings.ShowLocalExternalTopology = ShowLocalExternalTopologyCheck.IsChecked == true;
        Settings.ShowLowSignificanceExternalTopology = ShowLowSignificanceExternalTopologyCheck.IsChecked == true;
        Settings.ExcludeSensorHostTopologyConnections = ExcludeSensorHostTopologyConnectionsCheck.IsChecked == true;
        if (Settings.QuerySnmpDeviceInfo && string.IsNullOrWhiteSpace(Settings.SnmpCommunity))
        {
            ThemedMessageBox.Show("SNMP v2c 조회를 사용하려면 읽기 전용 Community를 입력하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
    }

    private void AuditSmbCheck_Changed(object sender, RoutedEventArgs e) => UpdateGuestShareState();
    private void SnmpQueryCheck_Changed(object sender, RoutedEventArgs e) => UpdateSnmpState();
    private void CaptureScopeCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) => UpdateCaptureScopeState();


    private PacketCaptureScopeMode GetSelectedCaptureScope()
    {
        if (CaptureScopeCombo?.SelectedItem is System.Windows.Controls.ComboBoxItem item &&
            string.Equals(item.Tag?.ToString(), "SpanTap", StringComparison.OrdinalIgnoreCase))
            return PacketCaptureScopeMode.SpanTap;
        return PacketCaptureScopeMode.LocalHost;
    }

    private void UpdateCaptureScopeState()
    {
        if (CaptureScopeCombo is null || ShowLocalExternalTopologyCheck is null || CaptureScopeHintText is null) return;
        bool span = GetSelectedCaptureScope() == PacketCaptureScopeMode.SpanTap;
        ShowLocalExternalTopologyCheck.IsEnabled = !span;
        if (span)
        {
            CaptureScopeHintText.Text = "SPAN/TAP 모드에서는 NetLoom이 실행 PC와 무관한 Transit Unicast를 실제로 관찰한 뒤에만 External/Public 관계도를 자동 확장합니다. Transit이 확인되지 않으면 외부 관계는 숨김 상태를 유지합니다.";
        }
        else
        {
            CaptureScopeHintText.Text = "LOCAL 기본값에서는 관찰 External/Public 노드를 관계도에서 숨겨 전체망 관제로 오해하지 않도록 합니다. 필요할 때만 위 제한 표시 옵션을 사용하세요.";
        }
    }

    private void UpdateGuestShareState()
    {
        if (GuestShareCheck is not null)
            GuestShareCheck.IsEnabled = AuditSmbCheck?.IsChecked == true;
    }

    private void UpdateSnmpState()
    {
        if (SnmpCommunityBox is not null)
            SnmpCommunityBox.IsEnabled = SnmpQueryCheck?.IsChecked == true;
        if (NestedDiscoveryCheck is not null)
            NestedDiscoveryCheck.IsEnabled = SnmpQueryCheck?.IsChecked == true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void Close_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }
}
