using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using NetLoom.App.Helpers;
using NetLoom.App.Models;
using NetLoom.App.Services;

namespace NetLoom.App.Windows;

public partial class PacketInspectorWindow : Window
{
    private const int MaxVisibleRows = 30000;
    private const int MaxPendingRows = 12000;

    private readonly PacketCaptureService _capture;
    private readonly Func<AdapterInfo?> _adapterProvider;
    private readonly Func<PacketCaptureScopeMode> _captureScopeProvider;
    private readonly Func<PacketObservation, PacketSecurityTag>? _securityClassifier;
    private readonly ConcurrentQueue<PacketObservation> _pending = new();
    private readonly ObservableCollection<PacketInspectorRow> _rows = new();
    private readonly DispatcherTimer _flushTimer;
    private PacketInspectorSettings _settings;
    private string[] _keywords = Array.Empty<string>();
    private long _received;
    private long _dropped;
    private long _matched;
    private StreamWriter? _auditWriter;
    private string _auditCsvPath = "";
    private DateTime? _auditStartedUtc;
    private long _auditPackets;
    private long _auditMatches;

    public ICollectionView PacketView { get; }

    public PacketInspectorWindow(PacketCaptureService capture, Func<AdapterInfo?> adapterProvider, Func<PacketCaptureScopeMode>? captureScopeProvider = null, string? initialFilter = null, Func<PacketObservation, PacketSecurityTag>? securityClassifier = null)
    {
        InitializeComponent();
        WindowSizingHelper.EnableWorkAreaMaximize(this);
        _capture = capture;
        _adapterProvider = adapterProvider;
        _captureScopeProvider = captureScopeProvider ?? (() => PacketCaptureScopeMode.LocalHost);
        _securityClassifier = securityClassifier;
        _settings = PacketInspectorSettingsService.Load();
        KeywordsBox.Text = _settings.Keywords.Replace("\n", ", ");
        PreviewCheck.IsChecked = _settings.InspectPlaintextPreview;
        _keywords = ParseKeywords(_settings.Keywords);

        PacketView = CollectionViewSource.GetDefaultView(_rows);
        PacketView.Filter = FilterRow;
        DataContext = this;
        if (!string.IsNullOrWhiteSpace(initialFilter))
            SearchBox.Text = initialFilter.Trim();

        _capture.PacketCaptured += Capture_PacketCaptured;
        _capture.CaptureStopped += Capture_CaptureStopped;
        _flushTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(120) };
        _flushTimer.Tick += FlushTimer_Tick;
        _flushTimer.Start();
        Closed += PacketInspectorWindow_Closed;
        UpdateCaptureState();
    }

    private void PacketInspectorWindow_Closed(object? sender, EventArgs e)
    {
        _flushTimer.Stop();
        StopAuditRecording(showCompletion: false);
        _capture.PacketCaptured -= Capture_PacketCaptured;
        _capture.CaptureStopped -= Capture_CaptureStopped;
    }

    private void Capture_PacketCaptured(PacketObservation packet)
    {
        Interlocked.Increment(ref _received);
        if (_pending.Count >= MaxPendingRows)
        {
            if (_pending.TryDequeue(out _)) Interlocked.Increment(ref _dropped);
        }
        _pending.Enqueue(packet);
    }

    private void Capture_CaptureStopped(string reason)
    {
        Dispatcher.BeginInvoke(new Action(() =>
        {
            // A packet-level audit cannot continue after the shared capture source stops.
            if (_auditWriter is not null)
                StopAuditRecording(showCompletion: false);
            UpdateCaptureState();
            if (!string.IsNullOrWhiteSpace(reason) && reason is not "사용자 중지" and not "캡처 종료")
                CaptureStateText.Text = $"STOP · {reason}";
        }));
    }

    private void FlushTimer_Tick(object? sender, EventArgs e)
    {
        UpdateCaptureState();
        bool pauseDisplay = PauseCheck.IsChecked == true;

        int flushed = 0;
        int visibleAdded = 0;
        while (flushed < 240 && _pending.TryDequeue(out var packet))
        {
            var row = BuildRow(packet);
            // Display pause only freezes the grid. Audit recording continues so packets are not
            // silently omitted from an active start/end audit session.
            if (!pauseDisplay)
            {
                if (row.HasKeywordHit) _matched++;
                _rows.Add(row);
                visibleAdded++;
            }
            AppendAuditRow(row);
            flushed++;
        }

        if (_rows.Count > MaxVisibleRows)
        {
            int remove = Math.Min(1000, _rows.Count - MaxVisibleRows + 500);
            for (int i = 0; i < remove && _rows.Count > 0; i++)
                _rows.RemoveAt(0);
        }

        if (visibleAdded > 0)
        {
            PacketView.Refresh();
            if (PacketGrid.Items.Count > 0)
                PacketGrid.ScrollIntoView(PacketGrid.Items[PacketGrid.Items.Count - 1]);
        }
        UpdateCounters();
    }

    private PacketInspectorRow BuildRow(PacketObservation packet)
    {
        string direction = string.Equals(packet.SourceIp, _capture.AdapterAddress, StringComparison.OrdinalIgnoreCase)
            ? "OUT"
            : string.Equals(packet.DestinationIp, _capture.AdapterAddress, StringComparison.OrdinalIgnoreCase)
                ? "IN"
                : "PASS";

        int? servicePort = ChooseServicePort(packet.SourcePort, packet.DestinationPort);
        string service = TrafficAuditFlowRecord.DescribeService(packet.Protocol, servicePort);
        PacketSecurityTag security = _securityClassifier?.Invoke(packet) ?? PacketSecurityTag.None;
        // Keyword matching may use visible packet bytes transiently, but the row keeps only
        // redacted/display-safe text so a later CSV/audit export cannot leak raw secrets.
        string rawMatchText = string.Join(" ", new[]
        {
            packet.SourceIp, packet.SourcePort?.ToString() ?? "", packet.DestinationIp, packet.DestinationPort?.ToString() ?? "", service, packet.TcpFlagsText,
            packet.ApplicationSummary, packet.InspectionText
        }.Where(x => !string.IsNullOrWhiteSpace(x)));
        string safeSearchText = string.Join(" ", new[]
        {
            packet.SourceIp, packet.SourcePort?.ToString() ?? "", packet.DestinationIp, packet.DestinationPort?.ToString() ?? "", service, packet.TcpFlagsText,
            packet.ApplicationSummary, packet.PayloadPreview
        }.Where(x => !string.IsNullOrWhiteSpace(x)));
        string hits = MatchKeywords(rawMatchText);

        return new PacketInspectorRow
        {
            TimestampUtc = packet.Timestamp,
            Direction = direction,
            Protocol = packet.Protocol,
            SourceIp = packet.SourceIp,
            SourcePort = packet.SourcePort,
            DestinationIp = packet.DestinationIp,
            DestinationPort = packet.DestinationPort,
            Service = service,
            Flags = packet.TcpFlagsText,
            Length = packet.Length,
            Summary = packet.ApplicationSummary,
            KeywordHits = hits,
            Preview = PreviewCheck?.IsChecked == true ? packet.PayloadPreview : "",
            SearchText = safeSearchText,
            IsExternalTraffic = security.IsExternal,
            IsSecuritySuspicious = security.IsSuspicious,
            IsBeaconCandidate = security.IsBeaconCandidate,
            IsBaselineAnomaly = security.IsBaselineAnomaly,
            IsLateralMovementCandidate = security.IsLateralMovementCandidate,
            IsDnsAnomaly = security.IsDnsAnomaly,
            IsPolicyException = security.IsPolicyException,
            SecurityLevel = security.RiskLevel,
            SecurityReason = security.Reason,
            IsTcpSyn = packet.IsTcpConnectionStart
        };
    }

    private string MatchKeywords(string text)
    {
        if (_keywords.Length == 0 || string.IsNullOrWhiteSpace(text)) return "";
        return string.Join(", ", _keywords.Where(k => text.Contains(k, StringComparison.OrdinalIgnoreCase)).Take(12));
    }

    private bool FilterRow(object item)
    {
        if (item is not PacketInspectorRow row) return false;
        if (OnlyKeywordCheck?.IsChecked == true && !row.HasKeywordHit) return false;
        if (OutgoingOnlyCheck?.IsChecked == true && !string.Equals(row.Direction, "OUT", StringComparison.OrdinalIgnoreCase)) return false;
        if (ExternalOnlyCheck?.IsChecked == true && !row.IsExternalTraffic) return false;
        if (SecurityOnlyCheck?.IsChecked == true && !row.IsSecuritySuspicious) return false;
        if (BeaconOnlyCheck?.IsChecked == true && !row.IsBeaconCandidate) return false;
        if (BaselineOnlyCheck?.IsChecked == true && !row.IsBaselineAnomaly) return false;
        if (LateralOnlyCheck?.IsChecked == true && !row.IsLateralMovementCandidate) return false;
        if (DnsAnomalyOnlyCheck?.IsChecked == true && !row.IsDnsAnomaly) return false;
        if (PolicyOnlyCheck?.IsChecked == true && !row.IsPolicyException) return false;
        if (SynOnlyCheck?.IsChecked == true && !row.IsTcpSyn) return false;

        string protocol = ProtocolFilterBox?.Text?.Trim() ?? "";
        if (!string.IsNullOrWhiteSpace(protocol) &&
            !row.Protocol.Contains(protocol, StringComparison.OrdinalIgnoreCase)) return false;

        string portFilter = PortFilterBox?.Text?.Trim() ?? "";
        if (!MatchesPortFilter(row, portFilter)) return false;

        string q = SearchBox?.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(q)) return true;
        return row.SourceIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.SourcePortText.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.DestinationIp.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.DestinationPortText.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.Protocol.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.Service.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.SecurityLevel.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.SecurityReason.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.Summary.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.KeywordHits.Contains(q, StringComparison.OrdinalIgnoreCase) ||
               row.Preview.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private static bool MatchesPortFilter(PacketInspectorRow row, string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        var values = filter.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (values.Length == 0) return true;
        foreach (string value in values)
        {
            if (int.TryParse(value, out int port) && (row.SourcePort == port || row.DestinationPort == port))
                return true;
            if (!int.TryParse(value, out _) && row.Service.Contains(value, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private async void Capture_Click(object sender, RoutedEventArgs e)
    {
        if (_capture.IsRunning)
        {
            if (_auditWriter is not null)
                StopAuditRecording(showCompletion: true);
            _capture.Stop();
            UpdateCaptureState();
            return;
        }

        var adapter = _adapterProvider();
        if (adapter is null)
        {
            ThemedMessageBox.Show("패킷 캡처에 사용할 IPv4 어댑터를 먼저 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            await _capture.StartAsync(adapter, _captureScopeProvider());
            UpdateCaptureState();
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show(
                $"패킷 캡처를 시작하지 못했습니다.\n\n{ex.Message}\n\nWindows Raw Socket 캡처는 관리자 권한이 필요할 수 있습니다. SPAN/TAP 모드는 실제 스위치 미러링이 먼저 구성되어야 하며, 드라이버가 Transit 프레임을 Raw Socket에 전달하지 않는 환경에서는 향후 Npcap Provider가 필요할 수 있습니다.",
                "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            UpdateCaptureState();
        }
    }

    private void SaveKeywords_Click(object sender, RoutedEventArgs e)
    {
        _settings.Keywords = NormalizeKeywordText(KeywordsBox.Text);
        _settings.InspectPlaintextPreview = PreviewCheck.IsChecked == true;
        _keywords = ParseKeywords(_settings.Keywords);
        PacketInspectorSettingsService.Save(_settings);

        _matched = 0;
        foreach (var row in _rows)
        {
            row.KeywordHits = MatchKeywords(row.SearchText);
            if (row.HasKeywordHit) _matched++;
        }
        PacketView.Refresh();
        PacketGrid.Items.Refresh();
        UpdateCounters();
    }

    private async void TraceRecord_Click(object sender, RoutedEventArgs e)
    {
        if (_auditWriter is not null)
        {
            StopAuditRecording(showCompletion: true);
            return;
        }

        if (!_capture.IsRunning)
        {
            var adapter = _adapterProvider();
            if (adapter is null)
            {
                ThemedMessageBox.Show("패킷 감사에 사용할 IPv4 어댑터를 먼저 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                await _capture.StartAsync(adapter, _captureScopeProvider());
            }
            catch (Exception ex)
            {
                ThemedMessageBox.Show(
                    $"패킷 캡처를 시작하지 못했습니다.\n\n{ex.Message}\n\n관리자 권한으로 NetLoom을 실행한 뒤 다시 시도하세요. SPAN/TAP 사용 시에는 미러 Destination NIC와 NetLoom 선택 어댑터가 동일한지도 확인하세요.",
                    "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
                UpdateCaptureState();
                return;
            }
        }

        try
        {
            StartAuditRecording();
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"감사 기록 파일을 만들지 못했습니다.\n\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        UpdateCaptureState();
    }

    private void StartAuditRecording()
    {
        string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string directory = Path.Combine(root, "WooklyDev", "NetLoom", "packet-trace-audit");
        Directory.CreateDirectory(directory);
        _auditStartedUtc = DateTime.UtcNow;
        _auditPackets = 0;
        _auditMatches = 0;
        _auditCsvPath = Path.Combine(directory, $"PacketTraceAudit_{DateTime.Now:yyyyMMdd_HHmmss_fff}.csv");
        _auditWriter = new StreamWriter(_auditCsvPath, false, new UTF8Encoding(true));
        _auditWriter.WriteLine("time,direction,protocol,source,source_port,destination,destination_port,service,security_level,security_reason,external,beacon,baseline_anomaly,lateral_movement,dns_anomaly,policy_exception,flags,length,summary,keywords,preview");
        _auditWriter.Flush();
        UpdateAuditState();
    }

    private void AppendAuditRow(PacketInspectorRow row)
    {
        if (_auditWriter is null) return;
        try
        {
            _auditWriter.WriteLine(ToCsvLine(row));
            _auditPackets++;
            if (row.HasKeywordHit) _auditMatches++;
            if ((_auditPackets % 100) == 0) _auditWriter.Flush();
        }
        catch (Exception ex)
        {
            string message = ex.Message;
            StopAuditRecording(showCompletion: false);
            AuditStateText.Text = $"기록 오류 · {message}";
            AuditStateText.Foreground = new SolidColorBrush(Color.FromRgb(255, 124, 112));
        }
    }

    private void StopAuditRecording(bool showCompletion)
    {
        if (_auditWriter is null) return;
        string path = _auditCsvPath;
        DateTime endedUtc = DateTime.UtcNow;
        DateTime? startedUtc = _auditStartedUtc;
        try
        {
            _auditWriter.Flush();
            _auditWriter.Dispose();
        }
        finally
        {
            _auditWriter = null;
        }

        try
        {
            string metadataPath = Path.ChangeExtension(path, ".meta.json");
            var metadata = new
            {
                Product = "NetLoom",
                StartedUtc = startedUtc,
                EndedUtc = endedUtc,
                DurationSeconds = startedUtc.HasValue ? Math.Max(0, (endedUtc - startedUtc.Value).TotalSeconds) : 0,
                AdapterAddress = _capture.AdapterAddress,
                CaptureScope = _capture.TakeCoverageSnapshot().ModeText,
                Coverage = _capture.TakeCoverageSnapshot().CoverageStateText,
                Packets = _auditPackets,
                KeywordMatches = _auditMatches,
                KeywordCount = _keywords.Length,
                PayloadPolicy = "Only display-safe/redacted preview is persisted. HTTPS/TLS payload is not decrypted."
            };
            File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // The CSV is the primary audit artifact; metadata failure must not invalidate it.
        }

        _auditStartedUtc = null;
        UpdateAuditState();
        if (showCompletion)
        {
            ThemedMessageBox.Show(
                $"패킷 감사 기록을 저장했습니다.\n\n{path}\n\n저장 파일에는 마스킹된 미리보기와 통신 메타데이터만 포함됩니다.",
                "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void UpdateAuditState()
    {
        if (AuditRecordButton is null || AuditStateText is null) return;
        bool recording = _auditWriter is not null;
        AuditRecordButton.Content = recording ? "■ 기록 종료" : "● 감사 기록";
        AuditStateText.Text = recording
            ? $"REC · {_auditPackets:N0} pkt · 키워드 {_auditMatches:N0}"
            : string.IsNullOrWhiteSpace(_auditCsvPath) ? "AUDIT OFF" : $"LAST · {Path.GetFileName(_auditCsvPath)}";
        AuditStateText.Foreground = new SolidColorBrush(recording ? Color.FromRgb(250, 216, 59) : Color.FromRgb(142, 142, 142));
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        _rows.Clear();
        while (_pending.TryDequeue(out _)) { }
        _received = 0;
        _dropped = 0;
        _matched = 0;
        UpdateCounters();
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_rows.Count == 0)
        {
            ThemedMessageBox.Show("저장할 패킷 기록이 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV (*.csv)|*.csv|All files (*.*)|*.*",
            FileName = $"NetLoom_PacketTrace_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };
        if (dialog.ShowDialog(this) != true) return;

        using var writer = new StreamWriter(dialog.FileName, false, new UTF8Encoding(true));
        writer.WriteLine("time,direction,protocol,source,source_port,destination,destination_port,service,security_level,security_reason,external,beacon,baseline_anomaly,lateral_movement,dns_anomaly,policy_exception,flags,length,summary,keywords,preview");
        foreach (var row in _rows)
            writer.WriteLine(ToCsvLine(row));
        CaptureStateText.Text = $"CSV 저장 · {Path.GetFileName(dialog.FileName)}";
    }

    private void UpdateCaptureState()
    {
        bool running = _capture.IsRunning;
        CaptureButton.Content = running ? "■ 캡처 중지" : "▶ 캡처 시작";
        CaptureButton.Background = new SolidColorBrush(running ? Color.FromRgb(42, 82, 64) : Color.FromRgb(250, 216, 59));
        CaptureButton.Foreground = new SolidColorBrush(running ? Color.FromRgb(235, 245, 240) : Color.FromRgb(23, 23, 23));
        CaptureStateText.Text = running ? $"LIVE · {_capture.AdapterAddress}" : "CAPTURE OFF";
        CaptureStateText.Foreground = new SolidColorBrush(running ? Color.FromRgb(98, 217, 166) : Color.FromRgb(142, 142, 142));
        var coverage = _capture.TakeCoverageSnapshot();
        var configuredScope = _captureScopeProvider();
        if (CoverageStateText is not null)
        {
            if (!running && coverage.Mode != configuredScope)
            {
                CoverageStateText.Text = configuredScope == PacketCaptureScopeMode.SpanTap
                    ? "SPAN 설정 · 캡처 시작 후 Transit 검증"
                    : "LOCAL HOST";
                CoverageStateText.Foreground = new SolidColorBrush(configuredScope == PacketCaptureScopeMode.SpanTap
                    ? Color.FromRgb(250, 216, 59)
                    : Color.FromRgb(158, 158, 158));
            }
            else
            {
                CoverageStateText.Text = coverage.Mode == PacketCaptureScopeMode.SpanTap
                    ? coverage.IsSpanVerified
                        ? $"SPAN 확인 · Transit {coverage.TransitPackets:N0}"
                        : $"SPAN 대기 · Transit {coverage.TransitPackets:N0}"
                    : "LOCAL HOST";
                CoverageStateText.Foreground = new SolidColorBrush(coverage.IsSpanVerified
                    ? Color.FromRgb(98, 217, 166)
                    : coverage.Mode == PacketCaptureScopeMode.SpanTap
                        ? Color.FromRgb(250, 216, 59)
                        : Color.FromRgb(158, 158, 158));
            }
        }
        UpdateAuditState();
        UpdateCounters();
    }

    private void UpdateCounters()
    {
        PacketCountText.Text = $"{Interlocked.Read(ref _received):N0} packets · 표시 {_rows.Count:N0}";
        MatchCountText.Text = $"{_matched:N0} matches";
        long dropped = Interlocked.Read(ref _dropped);
        DropText.Text = dropped > 0 ? $"대기열 초과 {dropped:N0}건 생략" : "";
    }

    private static int? ChooseServicePort(int? sourcePort, int? destinationPort)
    {
        static bool Known(int port) => port is
            20 or 21 or 22 or 23 or 25 or 53 or 67 or 68 or 80 or 110 or 123 or 135 or 137 or 138 or 139 or
            143 or 161 or 162 or 389 or 443 or 445 or 465 or 515 or 548 or 587 or 631 or 636 or 873 or 993 or
            995 or 1433 or 1521 or 1883 or 2049 or 3306 or 3389 or 5060 or 5061 or 5432 or 5900 or 6379 or
            8080 or 8443 or 8883 or 9100;
        if (destinationPort is int dp && Known(dp)) return dp;
        if (sourcePort is int sp && Known(sp)) return sp;
        return destinationPort ?? sourcePort;
    }

    private static string[] ParseKeywords(string value) => value
        .Replace("\r", "\n")
        .Split(new[] { '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(x => x.Length >= 2)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(100)
        .ToArray();

    private static string NormalizeKeywordText(string value) => string.Join(Environment.NewLine, ParseKeywords(value));

    private static string ToCsvLine(PacketInspectorRow row) => string.Join(',', new[]
    {
        Csv(row.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")), Csv(row.Direction), Csv(row.Protocol), Csv(row.SourceIp), Csv(row.SourcePortText),
        Csv(row.DestinationIp), Csv(row.DestinationPortText), Csv(row.Service), Csv(row.SecurityLevel), Csv(row.SecurityReason),
        row.IsExternalTraffic ? "1" : "0", row.IsBeaconCandidate ? "1" : "0", row.IsBaselineAnomaly ? "1" : "0", row.IsLateralMovementCandidate ? "1" : "0",
        row.IsDnsAnomaly ? "1" : "0", row.IsPolicyException ? "1" : "0",
        Csv(row.Flags), row.Length.ToString(), Csv(row.Summary), Csv(row.KeywordHits), Csv(row.Preview)
    });

    private static string Csv(string value) => NetLoom.App.Helpers.CsvHelper.Escape(value);

    private void SearchBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => PacketView?.Refresh();
    private void FilterTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => PacketView?.Refresh();
    private void FilterChanged(object sender, RoutedEventArgs e) => PacketView?.Refresh();

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
