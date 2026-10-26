using System.IO;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Microsoft.Win32;
using NetLoom.App.Helpers;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class TrafficAuditWindow : Window
{
    private sealed class FlowRow
    {
        public string FirstSeenText { get; init; } = "";
        public string LastSeenText { get; init; } = "";
        public string SourceDisplay { get; init; } = "";
        public string DestinationDisplay { get; init; } = "";
        public string ServiceText { get; init; } = "";
        public long ConnectionStarts { get; init; }
        public long Packets { get; init; }
        public long Bytes { get; init; }
        public string BytesText { get; init; } = "";
        public string SourceIp { get; init; } = "";
        public string DestinationIp { get; init; } = "";
        public string Protocol { get; init; } = "";
        public int? DestinationPort { get; init; }
    }

    private readonly Func<TrafficAuditSessionSnapshot> _snapshotProvider;
    private readonly Func<IEnumerable<ScanResult>> _resultsProvider;
    private readonly DispatcherTimer _timer;
    private TrafficAuditSessionSnapshot _snapshot = TrafficAuditSessionSnapshot.Empty;
    private List<FlowRow> _rows = new();

    public TrafficAuditWindow(Func<TrafficAuditSessionSnapshot> snapshotProvider, Func<IEnumerable<ScanResult>> resultsProvider)
    {
        InitializeComponent();
        WindowSizingHelper.EnableWorkAreaMaximize(this);
        _snapshotProvider = snapshotProvider;
        _resultsProvider = resultsProvider;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += (_, _) => RefreshView();
        Loaded += (_, _) => { RefreshView(); _timer.Start(); };
        Closed += (_, _) => _timer.Stop();
    }

    private void RefreshView()
    {
        _snapshot = _snapshotProvider();
        if (string.IsNullOrWhiteSpace(_snapshot.SessionId))
        {
            SessionTitleText.Text = "통신 감사 기록 없음";
            SessionTimeText.Text = "메인 화면에서 '기록 시작'을 눌러 감사 세션을 시작하세요.";
            StatusValueText.Text = "대기";
            DurationValueText.Text = "-";
            PacketValueText.Text = "0";
            ByteValueText.Text = "0 B";
            FlowValueText.Text = "0";
            PathText.Text = "패킷 본문은 저장하지 않으며 IPv4 헤더 기반 통신 메타데이터만 기록합니다.";
            _rows = new List<FlowRow>();
            FlowGrid.ItemsSource = _rows;
            return;
        }

        var names = _resultsProvider()
            .Where(r => r.IsOnline)
            .GroupBy(r => r.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(x => x.HostName).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "", StringComparer.OrdinalIgnoreCase);

        string Display(string ip) => names.TryGetValue(ip, out var name) && !string.IsNullOrWhiteSpace(name) ? $"{ip}  ·  {name}" : ip;
        _rows = _snapshot.Flows.Select(f => new FlowRow
        {
            FirstSeenText = f.FirstSeenText,
            LastSeenText = f.LastSeenText,
            SourceDisplay = Display(f.SourceIp),
            DestinationDisplay = Display(f.DestinationIp),
            ServiceText = f.ServiceText,
            ConnectionStarts = f.ConnectionStarts,
            Packets = f.Packets,
            Bytes = f.Bytes,
            BytesText = f.BytesText,
            SourceIp = f.SourceIp,
            DestinationIp = f.DestinationIp,
            Protocol = f.Protocol,
            DestinationPort = f.DestinationPort
        }).ToList();
        FlowGrid.ItemsSource = _rows;

        SessionTitleText.Text = _snapshot.IsRecording ? "● 통신 감사 기록 중" : "통신 감사 기록 완료";
        SessionTimeText.Text = $"시작 {_snapshot.StartedText} · 종료 {_snapshot.EndedText} · {_snapshot.AdapterDisplay}";
        StatusValueText.Text = _snapshot.IsRecording ? "기록 중" : "완료";
        StatusValueText.Foreground = new System.Windows.Media.SolidColorBrush(_snapshot.IsRecording
            ? System.Windows.Media.Color.FromRgb(98, 217, 166)
            : System.Windows.Media.Color.FromRgb(234, 234, 234));
        DurationValueText.Text = _snapshot.DurationText;
        PacketValueText.Text = _snapshot.TotalPackets.ToString("N0");
        ByteValueText.Text = _snapshot.TotalBytesText;
        FlowValueText.Text = $"{_snapshot.UniqueFlowCount:N0} · IP {_snapshot.UniqueNodeCount:N0}";
        PathText.Text = string.IsNullOrWhiteSpace(_snapshot.SavedPath)
            ? "기록 종료 시 JSON 원본이 %LOCALAPPDATA%\\WooklyDev\\NetLoom\\traffic-audit 에 자동 저장됩니다."
            : $"원본 JSON: {_snapshot.SavedPath}";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshView();

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(NetLoom.App.Services.TrafficAuditPersistenceService.AuditDirectory);
        Process.Start(new ProcessStartInfo(NetLoom.App.Services.TrafficAuditPersistenceService.AuditDirectory) { UseShellExecute = true });
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        RefreshView();
        if (_rows.Count == 0)
        {
            ThemedMessageBox.Show("내보낼 통신 기록이 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv",
            FileName = $"NetLoom_Traffic_Audit_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };
        if (dialog.ShowDialog() != true) return;

        static string Csv(string value) => NetLoom.App.Helpers.CsvHelper.Escape(value);
        var sb = new StringBuilder();
        sb.AppendLine("FirstSeen,LastSeen,Source,Destination,Protocol,DestinationPort,Service,ConnectionStarts,Packets,Bytes");
        foreach (var row in _rows)
        {
            sb.Append(Csv(row.FirstSeenText)).Append(',').Append(Csv(row.LastSeenText)).Append(',')
              .Append(Csv(row.SourceDisplay)).Append(',').Append(Csv(row.DestinationDisplay)).Append(',')
              .Append(Csv(row.Protocol)).Append(',').Append(row.DestinationPort?.ToString(CultureInfo.InvariantCulture) ?? "").Append(',')
              .Append(Csv(row.ServiceText)).Append(',').Append(row.ConnectionStarts.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(row.Packets.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(row.Bytes.ToString(CultureInfo.InvariantCulture)).AppendLine();
        }
        File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(true));
        PathText.Text = $"CSV 저장: {dialog.FileName}";
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
