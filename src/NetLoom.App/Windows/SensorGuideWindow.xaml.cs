using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using NetLoom.App.Helpers;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class SensorGuideWindow : Window
{
    private readonly Func<CaptureCoverageSnapshot> _coverageProvider;
    private readonly DispatcherTimer _refreshTimer;
    private CaptureCoverageSnapshot _coverage = CaptureCoverageSnapshot.Empty;

    public SensorGuideWindow(CaptureCoverageSnapshot coverage)
        : this(() => coverage ?? CaptureCoverageSnapshot.Empty)
    {
    }

    public SensorGuideWindow(Func<CaptureCoverageSnapshot> coverageProvider)
    {
        InitializeComponent();
        WindowSizingHelper.EnableWorkAreaMaximize(this);
        _coverageProvider = coverageProvider ?? (() => CaptureCoverageSnapshot.Empty);
        _refreshTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };
        _refreshTimer.Tick += (_, _) => RefreshCoverage();
        Loaded += (_, _) =>
        {
            RefreshCoverage();
            _refreshTimer.Start();
        };
        Closed += (_, _) => _refreshTimer.Stop();
    }

    private void RefreshCoverage()
    {
        try
        {
            _coverage = _coverageProvider() ?? CaptureCoverageSnapshot.Empty;
        }
        catch
        {
            _coverage = CaptureCoverageSnapshot.Empty;
        }

        ModeText.Text = _coverage.ModeText;
        CoverageText.Text = _coverage.CoverageStateText;
        PolicyText.Text = _coverage.TopologyPolicyText;
        CoverageText.Foreground = new SolidColorBrush(_coverage.IsSpanVerified
            ? Color.FromRgb(98, 217, 166)
            : _coverage.Mode == PacketCaptureScopeMode.SpanTap
                ? Color.FromRgb(250, 216, 59)
                : Color.FromRgb(218, 218, 218));

        if (CoverageDetailText is not null)
        {
            string lastTransit = _coverage.LastTransitSeenUtc == default
                ? "-"
                : _coverage.LastTransitSeenUtc.ToLocalTime().ToString("HH:mm:ss");
            CoverageDetailText.Text = $"전체 {_coverage.TotalPackets:N0} pkt · Local {_coverage.LocalEndpointPackets:N0} · Transit {_coverage.TransitPackets:N0} · External Transit {_coverage.TransitExternalPackets:N0} · 마지막 Transit {lastTransit}";
        }
    }

    private void CopyChecklist_Click(object sender, RoutedEventArgs e)
    {
        const string checklist = """
NetLoom SPAN / TAP 점검 체크리스트
1. 관리형 스위치 Mirror Source = Uplink 포트 또는 감사 VLAN
2. Mirror Destination = NetLoom 전용 NIC 연결 포트
3. 방향 = Ingress/Egress 또는 Both 확인
4. NetLoom 설정 > 패킷 관측 범위 = SPAN / TAP
5. NetLoom 어댑터 = 실제 미러 트래픽을 받는 물리 NIC
6. 실시간 통신 시작
7. 다른 사내 PC에서 정상 외부 통신 발생
8. 상태가 'SPAN 확인'으로 변경되고 Transit/내부 호스트 수가 증가하는지 확인
9. 확인 전에는 관찰 External/Public 관계도가 제한되는 것이 정상
10. SPAN 확인 후에도 관계도는 중요 Flow만 기본 표시하며 저중요 Flow는 패킷/분석에 계속 유지
""";
        try
        {
            Clipboard.SetText(checklist);
            PolicyText.Text = "SPAN/TAP 점검 체크리스트를 클립보드에 복사했습니다.";
            PolicyText.Foreground = new SolidColorBrush(Color.FromRgb(98, 217, 166));
        }
        catch
        {
            PolicyText.Text = "클립보드 복사에 실패했습니다.";
            PolicyText.Foreground = new SolidColorBrush(Color.FromRgb(255, 124, 112));
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
