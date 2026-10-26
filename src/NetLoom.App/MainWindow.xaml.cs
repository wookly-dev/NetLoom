using System.IO;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using NetLoom.App.Controls;
using NetLoom.App.Helpers;
using NetLoom.App.Models;
using NetLoom.App.Services;
using NetLoom.App.Windows;

namespace NetLoom.App;

public partial class MainWindow : Window
{
    public ObservableCollection<ScanResult> Results { get; } = new();
    public ObservableCollection<MatrixNode> MatrixNodes { get; } = new();
    public ObservableCollection<MatrixGroup> MatrixGroups { get; } = new();
    public ObservableCollection<EngineTraceEntry> EngineTraceEntries { get; } = new();
    private readonly List<EngineTraceEntry> _engineTraceHistory = new();
    public ICollectionView ResultsView { get; }

    private readonly NetworkScanner _scanner = new();
    private readonly PacketCaptureService _packetCapture = new();
    private readonly TrafficActivityTracker _trafficTracker = new();
    private readonly TrafficAuditRecorder _trafficAuditRecorder = new();
    private readonly ExternalIntelligenceService _externalIntelligenceService = new();
    private readonly ExternalObservationRegistry _externalObservationRegistry;
    private readonly SecurityRelationshipAnalyzer _securityRelationshipAnalyzer;
    private readonly SecurityTimelineRecorder _securityTimelineRecorder = new();
    private readonly DispatcherTimer _trafficUiTimer;
    private readonly List<ScanResult> _allResults = new();
    private readonly Dictionary<string, MatrixNode> _matrixLookup = new(StringComparer.OrdinalIgnoreCase);
    private readonly Stopwatch _scanStopwatch = new();

    private CancellationTokenSource? _scanCts;
    private AppSettings _settings;
    private ViewMode _viewMode = ViewMode.List;
    private int _onlineCount;
    private int _exposedCount;
    private int _guestExposureCount;
    private DateTime _lastScanStartedAt;
    private string _lastTargetExpression = "";
    private int[] _lastSelectedPorts = Array.Empty<int>();
    private string _lastAdapterDisplay = "";
    private IReadOnlyList<SubnetRecommendation> _scopeRecommendations = Array.Empty<SubnetRecommendation>();
    private readonly List<NestedNetworkInfo> _nestedNetworks = new();
    private IReadOnlyList<ScanTargetGroupDefinition> _lastTargetGroups = Array.Empty<ScanTargetGroupDefinition>();
    private TrafficSnapshot _trafficSnapshot = TrafficSnapshot.Empty;
    private TrafficAuditSessionSnapshot _trafficAuditSnapshot = TrafficAuditSessionSnapshot.Empty;
    private ExternalObservationSnapshot _externalObservationSnapshot = ExternalObservationSnapshot.Empty;
    private SecurityRelationshipSnapshot _securityRelationshipSnapshot = SecurityRelationshipSnapshot.Empty;
    private SecurityRelationshipSnapshot? _securityReplaySnapshot;
    private WifiAuditResult? _lastWifiAudit;
    private EngineTraceVerbosity _engineTraceVerbosity = EngineTraceVerbosity.Detailed;
    private ScanOptions? _activeScanOptions;
    private int _engineTotalHosts;
    private int _engineStartedHosts;
    private int _engineCompletedHosts;
    private int _engineConfiguredWorkers;
    private const int MaxEngineTraceEntries = 1200;
    private const int MaxEngineTraceHistoryEntries = 12000;
    private readonly ScaleTransform _topologyScaleTransform = new(0.80, 0.80);
    private double _topologyZoom = 0.80;
    private bool _syncingTopologyDisplayOptions;

    public MainWindow()
    {
        _externalObservationRegistry = new ExternalObservationRegistry(_externalIntelligenceService);
        _securityRelationshipAnalyzer = new SecurityRelationshipAnalyzer(null, null, _externalIntelligenceService);
        InitializeComponent();
        WindowSizingHelper.EnableWorkAreaMaximize(this);
        ResultsView = CollectionViewSource.GetDefaultView(Results);
        ResultsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(ScanResult.AuditGroupLabel)));
        ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanResult.AuditGroupLabel), ListSortDirection.Ascending));
        ResultsView.SortDescriptions.Add(new SortDescription(nameof(ScanResult.IpSortKey), ListSortDirection.Ascending));
        DataContext = this;
        _settings = SettingsService.Load();
        TopologyShowAllExternalCheck.IsChecked = _settings.ShowLowSignificanceExternalTopology;
        TopologyExcludeSensorHostConnectionsCheck.IsChecked = _settings.ExcludeSensorHostTopologyConnections;
        LoadAdapters();
        UpdateSelectedPortCount();
        SetViewMode(ViewMode.List);
        TopologyVisual.LayoutTransform = _topologyScaleTransform;
        ApplyTopologyZoom(0.80);
        TopologyVisual.SetData(Array.Empty<ScanResult>(), "");
        TopologyVisual.SetExternalObservationSnapshot(_externalObservationSnapshot);
        TopologyVisual.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
        TopologyVisual.SetIncludeLowSignificanceExternal(_settings.ShowLowSignificanceExternalTopology);
        TopologyVisual.SetExcludeSensorHostConnections(_settings.ExcludeSensorHostTopologyConnections);
        TopologyVisual.SetCaptureCoverageSnapshot(GetCaptureCoverageSnapshot());
        TopologyVisual.DeviceNodeClicked += TopologyVisual_DeviceNodeClicked;
        SetEngineVerbosity(EngineTraceVerbosity.Detailed);
        ResetEnginePanel();

        _packetCapture.PacketCaptured += packet =>
        {
            _trafficTracker.Add(packet);
            _trafficAuditRecorder.Add(packet);
            _externalObservationRegistry.Add(packet);
            _securityRelationshipAnalyzer.Add(packet);
        };
        _packetCapture.CaptureStopped += reason => Dispatcher.BeginInvoke(new Action(() => OnPacketCaptureStopped(reason)));
        _trafficUiTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(450)
        };
        _trafficUiTimer.Tick += TrafficUiTimer_Tick;
        _trafficUiTimer.Start();
        Closed += (_, _) =>
        {
            _trafficUiTimer.Stop();
            if (_trafficAuditRecorder.IsRecording)
            {
                try
                {
                    var ended = _trafficAuditRecorder.Stop("프로그램 종료");
                    var saved = TrafficAuditPersistenceService.SaveJsonAsync(ended).GetAwaiter().GetResult();
                    _trafficAuditRecorder.SetSavedPath(saved);
                }
                catch { }
            }
            _packetCapture.Stop();
            _securityRelationshipAnalyzer.FlushBaseline();
        };
        UpdateExternalHistoryUi();
        UpdatePacketCaptureUi();
    }

    private void LoadAdapters()
    {
        try
        {
            var adapters = NetworkAdapterService.GetAdapters();
            AdapterCombo.ItemsSource = adapters;

            if (adapters.Count > 0)
            {
                AdapterCombo.SelectedIndex = 0;
                FooterStatus.Text = $"어댑터 {adapters.Count}개 검색됨";
            }
            else
            {
                FooterStatus.Text = "사용 가능한 IPv4 어댑터를 찾지 못했습니다.";
            }
        }
        catch (Exception ex)
        {
            FooterStatus.Text = $"어댑터 조회 실패: {ex.Message}";
        }
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCts is not null)
            return;

        bool completedNormally = false;

        try
        {
            var target = ScanTargetParser.Parse(CidrTextBox.Text.Trim());
            var hosts = target.Hosts;
            var ports = ParsePorts(PortsTextBox.Text);
            int timeout = ParseBoundedInt(TimeoutTextBox.Text, 100, 10000, "타임아웃");
            int concurrency = ParseBoundedInt(ConcurrencyTextBox.Text, 1, 256, "동시 작업 수");

            if (!target.IsPrivateOrLocal)
            {
                var confirm = ThemedMessageBox.Show(
                    "사설/로컬 대역이 아닌 주소가 포함되어 있습니다.\n\n본인이 관리하거나 스캔 허가를 받은 네트워크인지 확인한 뒤 진행하세요.",
                    "NetLoom",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning);

                if (confirm != MessageBoxResult.OK)
                    return;
            }

            Results.Clear();
            _allResults.Clear();
            _onlineCount = 0;
            _exposedCount = 0;
            _guestExposureCount = 0;
            _nestedNetworks.Clear();
            _lastTargetGroups = target.Groups;
            TopologyVisual.SetNestedNetworks(Array.Empty<NestedNetworkInfo>());
            TopologyVisual.SetTopologyRoots(GetTopologyRootNetworks());
            EngineTraceEntries.Clear();
            _engineTraceHistory.Clear();
            _engineTotalHosts = hosts.Count;
            _engineStartedHosts = 0;
            _engineCompletedHosts = 0;
            _engineConfiguredWorkers = concurrency;
            ResetEnginePanel();
            SetEngineRunning(true);
            AddEngineTrace("RANGE", "", target.DisplayText, EngineTraceVerbosity.General);
            AddEngineTrace("QUEUE", "", $"{hosts.Count:N0} hosts · TCP {ports.Count:N0} ports · workers {concurrency}", EngineTraceVerbosity.General);
            HighlightPipelineStage("DISCOVER");
            PrepareMatrix(target.Groups);

            var auditGroupLookup = target.Groups
                .SelectMany(group => group.Hosts.Select(ip => new { Ip = ip.ToString(), Group = group }))
                .ToDictionary(x => x.Ip, x => x.Group, StringComparer.OrdinalIgnoreCase);

            var selectedAdapter = AdapterCombo.SelectedItem as AdapterInfo;
            string gateway = selectedAdapter?.GatewayAddress ?? "";
            var auditGroupGatewayLookup = BuildAuditGroupGatewayLookup(target.Groups, selectedAdapter);
            _lastScanStartedAt = DateTime.Now;
            _lastTargetExpression = target.NormalizedExpression;
            _lastSelectedPorts = ports.OrderBy(p => p).ToArray();
            _lastAdapterDisplay = selectedAdapter?.Display ?? "";
            TopologyVisual.SetData(Array.Empty<ScanResult>(), gateway);

            if (_settings.AutoSwitchToMatrix)
                SetViewMode(ViewMode.Matrix);

            _scanCts = new CancellationTokenSource();
            UpdateWifiAuditAvailability();
            _scanStopwatch.Restart();

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            ScanProgressBar.Value = 0;
            ScanPercentText.Text = "0%";
            ProgressText.Text = $"0 / {hosts.Count:N0}";
            StatusText.Text = $"스캔 중 · {target.DisplayText}";
            ScanDetailText.Text = _settings.AuditSmbShares
                ? $"TCP {ports.Count:N0} ports · ICMP + Connect + SMB Audit"
                : $"TCP {ports.Count:N0} ports · ICMP + Connect Audit";
            SummaryText.Text = $"스캔 준비 · {hosts.Count:N0}개 주소";
            FooterStatus.Text = "네트워크 감사 스캔 실행 중";
            StartScanPulse();

            var options = new ScanOptions
            {
                ResolveDns = _settings.ResolveDns,
                ResolveMac = _settings.ResolveMac,
                AuditSmbShares = _settings.AuditSmbShares,
                TestGuestShareAccess = _settings.TestGuestShareAccess,
                ProbeDeviceIdentity = _settings.ProbeDeviceIdentity,
                QueryIppPrinterInfo = _settings.QueryIppPrinterInfo,
                QuerySnmpDeviceInfo = _settings.QuerySnmpDeviceInfo,
                SnmpCommunity = _settings.SnmpCommunity,
                DiscoverNestedNetworks = _settings.DiscoverNestedNetworks,
                GatewayAddress = gateway,
                TraceVerbosity = _engineTraceVerbosity
            };
            _activeScanOptions = options;

            var startedProgress = new Progress<string>(ipAddress =>
            {
                _engineStartedHosts++;
                UpdateEngineStats();
                HighlightPipelineStage("PING");
                if (_matrixLookup.TryGetValue(ipAddress, out var node) && node.State == ScanNodeState.Pending)
                    node.State = ScanNodeState.Scanning;
            });

            var resultProgress = new Progress<ScanResult>(result =>
            {
                if (auditGroupLookup.TryGetValue(result.IpAddress, out var auditGroup))
                {
                    result.AuditGroupLabel = auditGroup.GroupLabel;
                    result.AuditGroupExpression = auditGroup.Expression;
                    if (auditGroupGatewayLookup.TryGetValue(auditGroup.GroupLabel, out var groupGateway))
                        result.AuditGatewayAddress = groupGateway;
                }

                _allResults.Add(result);
                _engineCompletedHosts++;
                UpdateEngineStats();

                if (_settings.ShowOfflineInList || result.IsOnline)
                    Results.Add(result);

                if (_matrixLookup.TryGetValue(result.IpAddress, out var node))
                    node.Apply(result);

                if (result.IsOnline) _onlineCount++;
                if (result.OpenPortNumbers.Count > 0) _exposedCount++;
                if (result.HasGuestShareExposure) _guestExposureCount++;

                SummaryText.Text = _guestExposureCount > 0
                    ? $"처리 {_allResults.Count:N0}개 · ONLINE {_onlineCount:N0}개 · 열린 포트 {_exposedCount:N0}개 · 게스트 공유 {_guestExposureCount:N0}개"
                    : $"처리 {_allResults.Count:N0}개 · ONLINE {_onlineCount:N0}개 · 열린 포트 {_exposedCount:N0}개";

                if (_settings.LiveTopologyRefresh && _viewMode == ViewMode.Topology && result.IsOnline)
                    TopologyVisual.SetData(_allResults, gateway);
            });

            var scanProgress = new Progress<(int Done, int Total)>(p =>
            {
                double percent = p.Total <= 0 ? 0 : p.Done * 100.0 / p.Total;
                ScanProgressBar.Value = percent;
                ScanPercentText.Text = $"{percent:0}%";
                ProgressText.Text = $"{p.Done:N0} / {p.Total:N0}";

                double seconds = Math.Max(0.001, _scanStopwatch.Elapsed.TotalSeconds);
                double rate = p.Done / seconds;
                EngineRateText.Text = $"{rate:0.0}/s";
                UpdateEngineStats();
                ScanDetailText.Text = _settings.AuditSmbShares
                    ? $"ONLINE {_onlineCount:N0} · {rate:0.0} hosts/s · TCP {ports.Count:N0} · SMB AUDIT"
                    : $"ONLINE {_onlineCount:N0} · {rate:0.0} hosts/s · TCP {ports.Count:N0}";
            });

            var traceProgress = new Progress<EngineTraceEntry>(entry =>
            {
                AddEngineTrace(entry);
                HighlightPipelineStage(entry.Category);
            });

            await _scanner.ScanAsync(
                hosts,
                ports,
                timeout,
                concurrency,
                options,
                resultProgress,
                scanProgress,
                startedProgress,
                traceProgress,
                _scanCts.Token);

            completedNormally = true;
            _scanStopwatch.Stop();
            ScanProgressBar.Value = 100;
            ScanPercentText.Text = "100%";

            StatusText.Text = _guestExposureCount > 0
                ? $"완료 · ONLINE {_onlineCount:N0}개 · 게스트 공유 노출 {_guestExposureCount:N0}개"
                : $"완료 · ONLINE {_onlineCount:N0}개 · 포트 노출 {_exposedCount:N0}개";
            ScanDetailText.Text = $"{_scanStopwatch.Elapsed.TotalSeconds:0.0}s · {_allResults.Count:N0} hosts processed";
            FooterStatus.Text = "스캔 완료 · 감사 보고서 생성 가능";

            if (_settings.DiscoverNestedNetworks && selectedAdapter is not null)
            {
                var discovered = NestedNetworkDiscoveryService.Discover(_allResults, selectedAdapter, target.Groups);
                _nestedNetworks.AddRange(discovered);
                TopologyVisual.SetNestedNetworks(_nestedNetworks);
                RefreshScopeRecommendations(selectedAdapter);

                int newSubnets = _nestedNetworks.Count(n => !n.IsCurrentScope);
                int routedSubnets = _nestedNetworks.Count(n => !n.IsCurrentScope && n.IsRouteConfirmed);
                if (newSubnets > 0)
                {
                    AddEngineTrace("DISCOVER", "", $"nested networks {newSubnets} · routed {routedSubnets}", EngineTraceVerbosity.General);
                    FooterStatus.Text = $"스캔 완료 · 하위 네트워크 {newSubnets:N0}개 발견 · 감사 대역 추천에서 확인";
                }
            }

            TopologyVisual.SetData(_allResults, gateway);
            TopologyVisual.SetTrafficSnapshot(_trafficSnapshot);
            AddEngineTrace("MAP", "", "topology dataset refreshed", EngineTraceVerbosity.General);
            AddEngineTrace("DONE", "", $"scan complete · {_onlineCount:N0} online · {_scanStopwatch.Elapsed.TotalSeconds:0.0}s", EngineTraceVerbosity.General);
            HighlightPipelineStage("MAP");
            SetEngineRunning(false, true);
        }
        catch (OperationCanceledException)
        {
            _scanStopwatch.Stop();
            StatusText.Text = "사용자에 의해 스캔이 중지되었습니다.";
            ScanDetailText.Text = $"중지 · {_allResults.Count:N0}개 결과 확보";
            FooterStatus.Text = "스캔 중지";
            AddEngineTrace("STOP", "", "scan cancelled by user", EngineTraceVerbosity.General);
            SetEngineRunning(false, false);
        }
        catch (Exception ex)
        {
            _scanStopwatch.Stop();
            StatusText.Text = $"오류 · {ex.Message}";
            FooterStatus.Text = "스캔 실패";
            AddEngineTrace("ERROR", "", ex.Message, EngineTraceVerbosity.General);
            SetEngineRunning(false, false);
            ThemedMessageBox.Show(ex.Message, "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            StopScanPulse(completedNormally);
            _scanCts?.Dispose();
            _scanCts = null;
            _activeScanOptions = null;
            UpdateWifiAuditAvailability();
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }
    }

    private async void PacketCapture_Click(object sender, RoutedEventArgs e)
    {
        if (_packetCapture.IsRunning)
        {
            if (_trafficAuditRecorder.IsRecording)
                await StopTrafficAuditAsync("실시간 캡처 중지");
            _packetCapture.Stop();
            AddEngineTrace("TRAFFIC", "", "packet capture stopped", EngineTraceVerbosity.General);
            UpdatePacketCaptureUi();
            return;
        }

        if (AdapterCombo.SelectedItem is not AdapterInfo adapter)
        {
            ThemedMessageBox.Show("패킷 캡처에 사용할 IPv4 어댑터를 먼저 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            _trafficTracker.Clear();
            _trafficSnapshot = TrafficSnapshot.Empty;
            await _packetCapture.StartAsync(adapter, _settings.PacketCaptureScope);
            AddEngineTrace("TRAFFIC", adapter.Address, $"packet capture started · {_settings.PacketCaptureScope} · metadata/application hints", EngineTraceVerbosity.General);
            UpdatePacketCaptureUi();
            FooterStatus.Text = "실시간 통신 캡처 시작 · 패킷 본문은 저장하지 않습니다.";
        }
        catch (SocketException ex)
        {
            ShowPacketCaptureStartError(ex.Message);
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"패킷 캡처 시작 오류\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
            UpdatePacketCaptureUi();
        }
    }

    private void PacketInspector_Click(object sender, RoutedEventArgs e) => OpenPacketInspectorWindow(null);

    private void OpenPacketInspectorWindow(string? initialFilter = null)
    {
        var window = new PacketInspectorWindow(
            _packetCapture,
            () => AdapterCombo.SelectedItem as AdapterInfo,
            () => _settings.PacketCaptureScope,
            initialFilter,
            _securityRelationshipAnalyzer.ClassifyPacket)
        {
            Owner = this
        };
        window.Show();
        FooterStatus.Text = "패킷 트레이서 열림 · 패킷 단위 통신/키워드 감사를 확인할 수 있습니다.";
    }

    private async void TrafficAudit_Click(object sender, RoutedEventArgs e)
    {
        await ToggleTrafficAuditAsync();
    }

    private async Task ToggleTrafficAuditAsync()
    {
        if (_trafficAuditRecorder.IsRecording)
        {
            await StopTrafficAuditAsync("사용자 종료");
            return;
        }

        if (AdapterCombo.SelectedItem is not AdapterInfo adapter)
        {
            ThemedMessageBox.Show("통신 감사에 사용할 IPv4 어댑터를 먼저 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            if (!_packetCapture.IsRunning)
            {
                _trafficTracker.Clear();
                _trafficSnapshot = TrafficSnapshot.Empty;
                await _packetCapture.StartAsync(adapter, _settings.PacketCaptureScope);
                AddEngineTrace("TRAFFIC", adapter.Address, "packet capture auto-started for audit recording", EngineTraceVerbosity.General);
            }

            _trafficAuditRecorder.Start(adapter);
            _trafficAuditSnapshot = _trafficAuditRecorder.TakeSnapshot();
            AddEngineTrace("AUDIT", adapter.Address, "traffic audit recording started", EngineTraceVerbosity.General);
            FooterStatus.Text = "통신 감사 기록 시작 · 출발지/목적지/프로토콜/포트/패킷량을 기록합니다.";
            UpdatePacketCaptureUi();
        }
        catch (SocketException ex)
        {
            ShowPacketCaptureStartError(ex.Message);
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"통신 감사 기록 시작 오류\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
            UpdatePacketCaptureUi();
        }
    }

    private async Task StopTrafficAuditAsync(string reason)
    {
        if (!_trafficAuditRecorder.IsRecording) return;
        var snapshot = _trafficAuditRecorder.Stop(reason);
        try
        {
            string savedPath = await TrafficAuditPersistenceService.SaveJsonAsync(snapshot);
            _trafficAuditRecorder.SetSavedPath(savedPath);
            _trafficAuditSnapshot = _trafficAuditRecorder.TakeSnapshot();
            FooterStatus.Text = $"통신 감사 기록 종료 · {_trafficAuditSnapshot.DurationText} · {_trafficAuditSnapshot.TotalPackets:N0} packets · JSON 자동 저장";
            AddEngineTrace("AUDIT", "", $"traffic audit stopped · {_trafficAuditSnapshot.TotalPackets:N0} packets · {_trafficAuditSnapshot.UniqueFlowCount:N0} flows", EngineTraceVerbosity.General);
        }
        catch (Exception ex)
        {
            _trafficAuditSnapshot = snapshot;
            FooterStatus.Text = $"통신 감사 기록 종료 · 자동 저장 실패: {ex.Message}";
            AddEngineTrace("AUDIT", "", $"record save failed · {ex.Message}", EngineTraceVerbosity.General);
        }
        UpdatePacketCaptureUi();
    }

    private void TrafficAuditView_Click(object sender, RoutedEventArgs e) => OpenTrafficAuditWindow();

    private void OpenTrafficAuditWindow()
    {
        var window = new TrafficAuditWindow(
            () => _trafficAuditRecorder.TakeSnapshot(),
            () => _allResults.ToList())
        {
            Owner = this
        };
        window.Show();
    }

    private void ShowPacketCaptureStartError(string message)
    {
        ThemedMessageBox.Show(
            $"실시간 패킷 캡처를 시작하지 못했습니다.\n\n{message}\n\nWindows Raw Socket 캡처는 관리자 권한이 필요할 수 있습니다. LOCAL HOST는 실행 PC 중심 관측입니다. SPAN/TAP 모드는 관리형 스위치의 미러 Destination을 NetLoom NIC에 연결해야 하며, 드라이버가 Transit 프레임을 Raw Socket에 전달하지 않는 환경에서는 향후 Npcap Provider가 필요할 수 있습니다.",
            "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
        UpdatePacketCaptureUi();
    }

    private void TrafficUiTimer_Tick(object? sender, EventArgs e)
    {
        _trafficSnapshot = _trafficTracker.TakeSnapshot();
        _trafficAuditSnapshot = _trafficAuditRecorder.TakeSnapshot(256, 512);
        _externalObservationSnapshot = _externalObservationRegistry.TakeSnapshot(512, 2048);
        _securityRelationshipSnapshot = _securityRelationshipAnalyzer.TakeSnapshot(512, 256);
        _securityTimelineRecorder.Record(_securityRelationshipSnapshot);
        TopologyVisual.SetTrafficSnapshot(_trafficSnapshot);
        TopologyVisual.SetTrafficAuditSnapshot(_trafficAuditSnapshot);
        TopologyVisual.SetTopologyAnalysisContext(
            _externalObservationSnapshot,
            GetDisplayedSecuritySnapshot(),
            GetCaptureCoverageSnapshot());
        UpdateExternalHistoryUi();
        UpdateSecurityRelationshipUi();
        UpdatePacketCaptureUi();
    }

    private async void OnPacketCaptureStopped(string reason)
    {
        if (PacketCaptureButton is null) return;
        if (_trafficAuditRecorder.IsRecording)
            await StopTrafficAuditAsync($"캡처 종료 · {reason}");
        UpdatePacketCaptureUi();
        if (!string.IsNullOrWhiteSpace(reason) && reason is not "사용자 중지" and not "캡처 종료")
        {
            AddEngineTrace("TRAFFIC", "", $"capture stopped · {reason}", EngineTraceVerbosity.General);
            FooterStatus.Text = $"실시간 통신 캡처 종료 · {reason}";
        }
    }

    private void UpdatePacketCaptureUi()
    {
        if (PacketCaptureButton is null || TrafficStatusText is null || TrafficStatusDot is null) return;
        bool running = _packetCapture.IsRunning;
        PacketCaptureButton.Content = running ? "■  실시간 통신 중지" : "◉  실시간 통신";
        PacketCaptureButton.Background = new SolidColorBrush(running ? Color.FromRgb(28, 55, 45) : Color.FromRgb(27, 27, 27));
        PacketCaptureButton.BorderBrush = new SolidColorBrush(running ? Color.FromRgb(61, 118, 91) : Color.FromRgb(58, 58, 58));
        TrafficStatusDot.Fill = new SolidColorBrush(running ? Color.FromRgb(98, 217, 166) : Color.FromRgb(91, 91, 91));
        TrafficStatusText.Text = running
            ? $"LIVE {_trafficSnapshot.CurrentRateText} · {_trafficSnapshot.CurrentPacketsPerSecond:0} pkt/s"
            : "TRAFFIC OFF";

        var coverage = GetCaptureCoverageSnapshot();
        if (CaptureCoverageStatusText is not null)
        {
            CaptureCoverageStatusText.Text = coverage.Mode == PacketCaptureScopeMode.SpanTap
                ? coverage.IsSpanVerified
                    ? $"SPAN 확인 · Transit {coverage.TransitPackets:N0} · Host {coverage.TransitInternalHostCount:N0}"
                    : $"SPAN 대기 · Transit {coverage.TransitPackets:N0}"
                : coverage.AllowLocalExternalTopology ? "LOCAL HOST · 외부 제한 표시" : "LOCAL HOST · 외부 관계 제한";
            CaptureCoverageStatusText.Foreground = new SolidColorBrush(coverage.IsSpanVerified
                ? Color.FromRgb(98, 217, 166)
                : coverage.Mode == PacketCaptureScopeMode.SpanTap
                    ? Color.FromRgb(250, 216, 59)
                    : Color.FromRgb(167, 167, 167));
        }
        if (TopologyCoverageText is not null)
        {
            TopologyCoverageText.Text = coverage.Mode == PacketCaptureScopeMode.SpanTap
                ? coverage.IsSpanVerified ? "SPAN 확인 · 외부 관계 활성" : "SPAN 미확인 · 외부 관계 제한"
                : coverage.AllowLocalExternalTopology ? "LOCAL · 외부 제한 표시" : "LOCAL · 외부 관계 숨김";
            TopologyCoverageText.Foreground = CaptureCoverageStatusText?.Foreground ?? new SolidColorBrush(Color.FromRgb(154, 154, 154));
            TopologyCoverageText.ToolTip = coverage.TopologyPolicyText;
        }

        if (TrafficAuditButton is null || TrafficAuditStatusText is null || TrafficAuditStatusDot is null || TrafficAuditViewButton is null) return;
        bool recording = _trafficAuditRecorder.IsRecording;
        var audit = _trafficAuditSnapshot;
        TrafficAuditButton.Content = recording ? "■  기록 종료" : "●  기록 시작";
        TrafficAuditButton.Background = new SolidColorBrush(recording ? Color.FromRgb(67, 48, 22) : Color.FromRgb(27, 27, 27));
        TrafficAuditButton.BorderBrush = new SolidColorBrush(recording ? Color.FromRgb(125, 100, 36) : Color.FromRgb(58, 58, 58));
        TrafficAuditStatusDot.Fill = new SolidColorBrush(recording ? Color.FromRgb(250, 216, 59) : Color.FromRgb(91, 91, 91));
        TrafficAuditStatusText.Text = recording
            ? $"REC {audit.DurationText} · {audit.TotalPackets:N0} pkt"
            : audit.HasData ? $"LAST {audit.DurationText} · {audit.TotalPackets:N0} pkt" : "AUDIT OFF";
        TrafficAuditStatusText.Foreground = new SolidColorBrush(recording ? Color.FromRgb(250, 216, 59) : Color.FromRgb(142, 142, 142));
        TrafficAuditViewButton.IsEnabled = audit.HasData || recording;
    }

    private void StopScan_Click(object sender, RoutedEventArgs e)
    {
        _scanCts?.Cancel();
        StopButton.IsEnabled = false;
        FooterStatus.Text = "중지 요청 처리 중";
    }

    private void ClearResults_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCts is not null)
            return;

        Results.Clear();
        _allResults.Clear();
        _onlineCount = 0;
        _exposedCount = 0;
        _guestExposureCount = 0;
        _lastTargetExpression = "";
        _lastSelectedPorts = Array.Empty<int>();
        MatrixNodes.Clear();
        MatrixGroups.Clear();
        _matrixLookup.Clear();
        _nestedNetworks.Clear();
        _lastTargetGroups = Array.Empty<ScanTargetGroupDefinition>();
        TopologyVisual.SetNestedNetworks(Array.Empty<NestedNetworkInfo>());
        TopologyVisual.SetTopologyRoots(Array.Empty<TopologyRootNetwork>());
        TopologyVisual.SetData(Array.Empty<ScanResult>(), GetSelectedGateway());

        SummaryText.Text = "결과 0개";
        ProgressText.Text = "0 / 0";
        ScanProgressBar.Value = 0;
        ScanPercentText.Text = "0%";
        StatusText.Text = "대기 중 · 스캔 범위와 포트를 확인하세요.";
        ScanDetailText.Text = "READY · ICMP + TCP Connect";
        MatrixTitleText.Text = "감사 대역 매트릭스";
        MatrixHintText.Text = "대역별 그룹 안에서 IP 끝자리와 장치 상태를 표시합니다.";
        FooterStatus.Text = "결과 지움";
        EngineTraceEntries.Clear();
        _engineTraceHistory.Clear();
        ResetEnginePanel();
    }

    private async void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.Count == 0)
        {
            FooterStatus.Text = "내보낼 결과가 없습니다.";
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "CSV 파일 (*.csv)|*.csv",
            FileName = $"NetLoom_Audit_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };

        if (dialog.ShowDialog() != true) return;

        await ExportService.ExportCsvAsync(dialog.FileName, _allResults);
        FooterStatus.Text = $"CSV 저장 완료 · {dialog.FileName}";
    }

    private async void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.Count == 0)
        {
            FooterStatus.Text = "내보낼 결과가 없습니다.";
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "JSON 파일 (*.json)|*.json",
            FileName = $"NetLoom_Audit_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };

        if (dialog.ShowDialog() != true) return;

        await ExportService.ExportJsonAsync(dialog.FileName, _allResults);
        FooterStatus.Text = $"JSON 저장 완료 · {dialog.FileName}";
    }

    private async void AuditReport_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCts is not null)
        {
            ThemedMessageBox.Show("스캔이 끝난 뒤 감사 보고서를 생성하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_allResults.Count == 0)
        {
            ThemedMessageBox.Show("보고서에 포함할 스캔 결과가 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Filter = "HTML 감사 보고서 (*.html)|*.html",
            FileName = $"NetLoom_Audit_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            FooterStatus.Text = "감사 보고서 생성 중";
            AddEngineTrace("REPORT", "", "audit report generation start", EngineTraceVerbosity.General);
            HighlightPipelineStage("REPORT");
            var context = new AuditReportContext
            {
                ScanStartedAt = _lastScanStartedAt,
                ScanDuration = _scanStopwatch.Elapsed,
                AdapterDisplay = _lastAdapterDisplay,
                TargetExpression = string.IsNullOrWhiteSpace(_lastTargetExpression) ? CidrTextBox.Text.Trim() : _lastTargetExpression,
                GatewayAddress = GetSelectedGateway(),
                SelectedPorts = _lastSelectedPorts.Length > 0 ? _lastSelectedPorts : ParsePorts(PortsTextBox.Text).OrderBy(p => p).ToArray(),
                WifiAudit = _lastWifiAudit,
                NestedNetworks = _nestedNetworks.ToArray(),
                TrafficSnapshot = _trafficSnapshot,
                TrafficAuditSession = _trafficAuditRecorder.TakeSnapshot(),
                SecurityRelationship = _securityRelationshipAnalyzer.TakeSnapshot(512, 256),
                ExternalObservation = _externalObservationRegistry.TakeSnapshot(512, 2048),
                CaptureCoverage = GetCaptureCoverageSnapshot(),
                IncludeLowSignificanceExternalTopology = _settings.ShowLowSignificanceExternalTopology,
                ExcludeSensorHostTopologyConnections = _settings.ExcludeSensorHostTopologyConnections
            };

            byte[]? topologyPng = TryRenderTopologyPngBytes();
            await AuditReportService.GenerateHtmlAsync(dialog.FileName, _allResults, context, topologyPng);
            FooterStatus.Text = $"감사 보고서 저장 완료 · {dialog.FileName}";
            AddEngineTrace("REPORT", "", $"saved · {Path.GetFileName(dialog.FileName)}", EngineTraceVerbosity.General);

            var open = ThemedMessageBox.Show(
                "감사 보고서가 생성되었습니다.\n\n지금 열어보시겠습니까?\n보고서 상단의 인쇄 / PDF 버튼으로 바로 출력할 수 있습니다.",
                "NetLoom",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);
            if (open == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            FooterStatus.Text = "감사 보고서 생성 실패";
            ThemedMessageBox.Show($"감사 보고서 생성에 실패했습니다.\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private byte[]? TryRenderTopologyPngBytes()
    {
        try
        {
            var outputSize = GetRecommendedTopologyOutputSize();
            int width = (int)Math.Ceiling(outputSize.Width);
            int height = (int)Math.Ceiling(outputSize.Height);
            var topology = CreateTopologyOutputVisual(width, height);
            var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(topology);
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var ms = new MemoryStream();
            encoder.Save(ms);
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private TopologyControl CreateTopologyOutputVisual(double width, double height)
    {
        var topology = new TopologyControl
        {
            AutoSizeCanvas = false,
            Width = Math.Max(1, width),
            Height = Math.Max(1, height),
            LightTheme = _settings.LightTopologyOutput,
            PerspectiveMode = false
        };
        topology.SetNestedNetworks(_nestedNetworks);
        topology.SetTopologyRoots(GetTopologyRootNetworks());
        topology.SetTrafficSnapshot(_trafficSnapshot);
        topology.SetTrafficAuditSnapshot(_trafficAuditSnapshot);
        topology.SetExternalObservationSnapshot(_externalObservationSnapshot);
        topology.SetCaptureCoverageSnapshot(GetCaptureCoverageSnapshot());
        topology.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
        topology.SetIncludeLowSignificanceExternal(_settings.ShowLowSignificanceExternalTopology);
        topology.SetExcludeSensorHostConnections(_settings.ExcludeSensorHostTopologyConnections);
        topology.SetData(_allResults, GetSelectedGateway());
        topology.Measure(new Size(topology.Width, topology.Height));
        topology.Arrange(new Rect(0, 0, topology.Width, topology.Height));
        topology.UpdateLayout();
        return topology;
    }

    private Size GetRecommendedTopologyOutputSize()
    {
        var probe = new TopologyControl { AutoSizeCanvas = true };
        probe.SetNestedNetworks(_nestedNetworks);
        probe.SetTopologyRoots(GetTopologyRootNetworks());
        probe.SetTrafficSnapshot(_trafficSnapshot);
        probe.SetTrafficAuditSnapshot(_trafficAuditSnapshot);
        probe.SetExternalObservationSnapshot(_externalObservationSnapshot);
        probe.SetCaptureCoverageSnapshot(GetCaptureCoverageSnapshot());
        probe.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
        probe.SetIncludeLowSignificanceExternal(_settings.ShowLowSignificanceExternalTopology);
        probe.SetExcludeSensorHostConnections(_settings.ExcludeSensorHostTopologyConnections);
        probe.SetData(_allResults, GetSelectedGateway());
        var size = probe.RecommendedCanvasSize;
        return new Size(Math.Max(1200, size.Width), Math.Max(700, size.Height));
    }

    private void RangePicker_Click(object sender, RoutedEventArgs e)
    {
        var window = new RangePickerWindow(AdapterCombo.SelectedItem as AdapterInfo, CidrTextBox.Text)
        {
            Owner = this
        };
        if (window.ShowDialog() != true) return;
        CidrTextBox.Text = window.TargetExpression;
        FooterStatus.Text = $"검색 범위 설정 · {window.TargetExpression}";
    }

    private void UseAdapterSubnet_Click(object sender, RoutedEventArgs e)
    {
        if (AdapterCombo.SelectedItem is not AdapterInfo adapter) return;
        CidrTextBox.Text = BuildNetworkCidr(adapter.Address, adapter.PrefixLength);
        FooterStatus.Text = $"현재 어댑터 대역 · {CidrTextBox.Text}";
    }

    private void UseSlash24_Click(object sender, RoutedEventArgs e)
    {
        if (AdapterCombo.SelectedItem is not AdapterInfo adapter) return;
        CidrTextBox.Text = BuildNetworkCidr(adapter.Address, 24);
        FooterStatus.Text = $"/24 빠른 범위 · {CidrTextBox.Text}";
    }

    private void RecommendedScopes_Click(object sender, RoutedEventArgs e)
    {
        if (AdapterCombo.SelectedItem is not AdapterInfo adapter)
        {
            ThemedMessageBox.Show("먼저 IPv4 어댑터를 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        RefreshScopeRecommendations(adapter);
        var window = new SubnetRecommendationWindow(adapter, _scopeRecommendations) { Owner = this };
        if (window.ShowDialog() != true) return;

        CidrTextBox.Text = window.TargetExpression;
        try
        {
            var target = ScanTargetParser.Parse(CidrTextBox.Text);
            FooterStatus.Text = $"추천 감사 범위 적용 · {target.Groups.Count:N0}개 대역 · {target.Hosts.Count:N0} IP";
        }
        catch
        {
            FooterStatus.Text = "추천 감사 범위 적용";
        }
    }

    private void RefreshScopeRecommendations(AdapterInfo adapter)
    {
        var baseItems = NetworkScopeDiscoveryService.GetRecommendations(adapter).ToList();
        var knownCidrs = baseItems.Select(x => x.Cidr).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var nested in NestedNetworkDiscoveryService.ToRecommendations(_nestedNetworks))
        {
            if (knownCidrs.Add(nested.Cidr))
                baseItems.Add(nested);
        }
        _scopeRecommendations = baseItems;

        int routedRemote = _scopeRecommendations.Count(x => !string.Equals(x.Source, "직접 연결", StringComparison.OrdinalIgnoreCase) &&
                                                           !string.Equals(x.Reachability, "대역 발견 · 경로 미확인", StringComparison.OrdinalIgnoreCase));
        int nestedCount = _nestedNetworks.Count(n => !n.IsCurrentScope);
        RecommendedScopeButton.IsEnabled = _scopeRecommendations.Count > 0;
        RecommendedScopeButton.Content = nestedCount > 0
            ? $"◎  감사 대역 추천  {_scopeRecommendations.Count:N0} · 하위 {nestedCount:N0}"
            : routedRemote > 0 ? $"◎  감사 대역 추천  {_scopeRecommendations.Count:N0}" : "◎  감사 대역 추천";

        RecommendedScopeText.Text = nestedCount > 0
            ? $"SNMP에서 하위 네트워크 {nestedCount:N0}개를 발견했습니다. 라우팅 확인/경로 미확인 상태를 구분해 감사 범위에 추가할 수 있습니다."
            : routedRemote > 0
                ? $"현재 PC에서 도달 가능한 다른 사설 대역 {routedRemote:N0}개를 추가로 감지했습니다. 다른 활성 어댑터의 직접 연결망도 포함됩니다."
                : "현재는 선택 어댑터의 직접 연결 대역만 추천됩니다.";
    }

    private void PortPicker_Click(object sender, RoutedEventArgs e)
    {
        IReadOnlyCollection<int> current;
        try
        {
            current = ParsePorts(PortsTextBox.Text);
        }
        catch
        {
            current = Array.Empty<int>();
        }

        var catalogPorts = CommonPortCatalog.All.Select(p => p.Port).ToHashSet();
        var customPorts = current.Where(p => !catalogPorts.Contains(p)).ToArray();

        var picker = new PortPickerWindow(current) { Owner = this };
        if (picker.ShowDialog() != true) return;

        var merged = picker.SelectedPorts.Concat(customPorts).Distinct().OrderBy(p => p).ToArray();
        if (merged.Length > 64)
        {
            ThemedMessageBox.Show("기존 커스텀 포트를 포함하면 64개를 초과합니다. 포트 선택을 줄여주세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        PortsTextBox.Text = string.Join(",", merged);
        FooterStatus.Text = $"TCP 포트 {merged.Length:N0}개 선택됨";
    }

    private async void Settings_Click(object sender, RoutedEventArgs e)
    {
        var oldScope = _settings.PacketCaptureScope;
        var window = new SettingsWindow(_settings) { Owner = this };
        if (window.ShowDialog() != true) return;

        _settings = window.Settings;
        try
        {
            SettingsService.Save(_settings);
            if (_packetCapture.IsRunning && oldScope != _settings.PacketCaptureScope)
            {
                if (_trafficAuditRecorder.IsRecording)
                    await StopTrafficAuditAsync("패킷 관측 범위 변경");
                _packetCapture.Stop();
                FooterStatus.Text = "패킷 관측 범위가 변경되어 기존 캡처를 중지했습니다. 다시 시작하면 새 모드가 적용됩니다.";
            }
            else
            {
                FooterStatus.Text = "설정 저장 완료";
            }
            RefreshVisibleResults();
            _syncingTopologyDisplayOptions = true;
            try
            {
                TopologyShowAllExternalCheck.IsChecked = _settings.ShowLowSignificanceExternalTopology;
                TopologyExcludeSensorHostConnectionsCheck.IsChecked = _settings.ExcludeSensorHostTopologyConnections;
            }
            finally
            {
                _syncingTopologyDisplayOptions = false;
            }
            TopologyVisual.SetIncludeLowSignificanceExternal(_settings.ShowLowSignificanceExternalTopology);
            TopologyVisual.SetExcludeSensorHostConnections(_settings.ExcludeSensorHostTopologyConnections);
            TopologyVisual.SetCaptureCoverageSnapshot(GetCaptureCoverageSnapshot());
            UpdateExternalHistoryUi();
            UpdatePacketCaptureUi();
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"설정 저장에 실패했습니다.\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void Info_Click(object sender, RoutedEventArgs e)
    {
        new InfoWindow { Owner = this }.ShowDialog();
    }

    private void SensorGuide_Click(object sender, RoutedEventArgs e)
    {
        new SensorGuideWindow(GetCaptureCoverageSnapshot) { Owner = this }.ShowDialog();
    }

    private void RefreshVisibleResults()
    {
        Results.Clear();
        foreach (var result in _allResults)
        {
            if (_settings.ShowOfflineInList || result.IsOnline)
                Results.Add(result);
        }
    }

    private void PrepareMatrix(IReadOnlyList<ScanTargetGroupDefinition> groups)
    {
        MatrixNodes.Clear();
        MatrixGroups.Clear();
        _matrixLookup.Clear();

        const int maxPerGroup = 256;
        const int maxTotalVisible = 1024;
        int visibleTotal = 0;

        foreach (var group in groups)
        {
            if (visibleTotal >= maxTotalVisible) break;

            int take = Math.Min(maxPerGroup, maxTotalVisible - visibleTotal);
            var matrixGroup = new MatrixGroup
            {
                GroupLabel = group.GroupLabel,
                Expression = group.Expression,
                HostCount = group.Hosts.Count
            };

            foreach (var ip in group.Hosts.Take(take))
            {
                var node = new MatrixNode
                {
                    IpAddress = ip.ToString(),
                    AddressLabel = MakeMatrixAddressLabel(ip, group.PrefixLengthHint),
                    GroupLabel = group.GroupLabel,
                    GroupExpression = group.Expression,
                    State = ScanNodeState.Pending,
                    DeviceType = DeviceType.Unknown
                };
                matrixGroup.Nodes.Add(node);
                MatrixNodes.Add(node);
                _matrixLookup[node.IpAddress] = node;
                visibleTotal++;
            }

            MatrixGroups.Add(matrixGroup);
        }

        int totalHosts = groups.Sum(g => g.Hosts.Count);
        MatrixTitleText.Text = groups.Count <= 1
            ? $"감사 대역 매트릭스 · {visibleTotal:N0} 포인트"
            : $"감사 대역 {groups.Count:N0}개 · {visibleTotal:N0} 포인트";

        if (totalHosts > visibleTotal)
        {
            MatrixHintText.Text = $"전체 {totalHosts:N0} IP 중 {visibleTotal:N0} 포인트를 표시합니다. 대역별 최대 256, 전체 최대 1,024 포인트이며 전체 결과는 리스트/보고서에 포함됩니다.";
        }
        else
        {
            MatrixHintText.Text = groups.Count > 1
                ? "각 감사 대역을 별도 그룹으로 나눠 같은 끝자리 IP도 혼동 없이 표시합니다."
                : "포인트를 클릭하면 장비/포트/공유폴더 상세 정보를 확인할 수 있습니다.";
        }
    }

    private static string MakeMatrixAddressLabel(IPAddress ip, int prefixLength)
    {
        var b = ip.GetAddressBytes();
        if (prefixLength >= 24) return b[3].ToString(CultureInfo.InvariantCulture);
        if (prefixLength >= 16) return $"{b[2]}.{b[3]}";
        return ip.ToString();
    }

    private void TopologyVisual_DeviceNodeClicked(ScanResult result)
    {
        OpenDeviceDetail(result);
    }

    private void ResultsGrid_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source) return;
        var row = FindVisualParent<DataGridRow>(source);
        if (row?.Item is ScanResult result)
            OpenDeviceDetail(result);
    }

    private void MatrixNode_Click(object sender, MouseButtonEventArgs e)
    {
        // Mark the routed mouse event handled before opening another Window.
        // Opening ShowDialog() from inside the still-active MouseUp route can cause
        // re-entrant input/window processing on some Windows/WPF environments.
        e.Handled = true;

        if (sender is not FrameworkElement { DataContext: MatrixNode node }) return;
        if (node.Result is null)
        {
            FooterStatus.Text = $"{node.GroupLabel} · {node.IpAddress} · {node.StateText}";
            return;
        }

        var result = node.Result;
        Dispatcher.BeginInvoke(
            DispatcherPriority.Background,
            new Action(() => OpenDeviceDetail(result)));
    }

    private bool _deviceDetailOpening;

    private void OpenDeviceDetail(ScanResult result)
    {
        if (_deviceDetailOpening) return;

        _deviceDetailOpening = true;
        try
        {
            var window = new DeviceDetailWindow(result, _securityRelationshipSnapshot.FindNode(result.IpAddress));
            if (IsLoaded && IsVisible)
                window.Owner = this;

            window.ShowDialog();
        }
        catch (Exception ex)
        {
            string logPath = CrashLogService.Write("DeviceDetailWindow", ex);
            string rootMessage = ex.GetBaseException().Message;
            FooterStatus.Text = "장비 상세창 오류 · 로그 저장됨";
            ThemedMessageBox.Show(
                $"장비 상세창을 여는 중 오류가 발생했습니다.\n\n{rootMessage}\n\n로그: {logPath}",
                "NetLoom",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            _deviceDetailOpening = false;
        }
    }

    private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
    {
        DependencyObject? current = child;
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private void ListMode_Click(object sender, RoutedEventArgs e) => SetViewMode(ViewMode.List);
    private void MatrixMode_Click(object sender, RoutedEventArgs e) => SetViewMode(ViewMode.Matrix);
    private void TopologyMode_Click(object sender, RoutedEventArgs e)
    {
        TopologyVisual.SetData(_allResults, GetSelectedGateway());
        _externalObservationSnapshot = _externalObservationRegistry.TakeSnapshot(512, 2048);
        TopologyVisual.SetExternalObservationSnapshot(_externalObservationSnapshot);
        UpdateExternalHistoryUi();
        SetViewMode(ViewMode.Topology);
        Dispatcher.BeginInvoke(new Action(() =>
        {
            if (_topologyZoom < 0.31 || _topologyZoom > 2.45)
                ApplyTopologyZoom(0.80);
        }));
    }

    private void TopologyFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (TopologyVisual is null) return;
        var categories = new List<TopologyCategory>();
        if (TopologyFilterInfra?.IsChecked == true) categories.Add(TopologyCategory.Infrastructure);
        if (TopologyFilterSpecial?.IsChecked == true) categories.Add(TopologyCategory.Special);
        if (TopologyFilterPeripheral?.IsChecked == true) categories.Add(TopologyCategory.Peripheral);
        if (TopologyFilterEndpoint?.IsChecked == true) categories.Add(TopologyCategory.Endpoint);
        if (TopologyFilterOther?.IsChecked == true) categories.Add(TopologyCategory.Other);
        if (TopologyFilterExternal?.IsChecked == true) categories.Add(TopologyCategory.External);
        TopologyVisual.SetHighlightedCategories(categories);
    }

    private void TopologyFilterReset_Click(object sender, RoutedEventArgs e)
    {
        TopologyFilterInfra.IsChecked = false;
        TopologyFilterSpecial.IsChecked = false;
        TopologyFilterPeripheral.IsChecked = false;
        TopologyFilterEndpoint.IsChecked = false;
        TopologyFilterOther.IsChecked = false;
        TopologyFilterExternal.IsChecked = false;
        TopologyVisual.SetHighlightedCategories(Array.Empty<TopologyCategory>());
    }

    private void TopologyExternalHistoryClear_Click(object sender, RoutedEventArgs e)
    {
        _externalObservationSnapshot = _externalObservationRegistry.TakeSnapshot(512, 2048);
        if (!_externalObservationSnapshot.HasData) return;

        var answer = ThemedMessageBox.Show(
            $"현재까지 관찰한 외부/Public IP {_externalObservationSnapshot.Count:N0}개와 외부 통신 관계 이력을 지우시겠습니까?\n\n실제 스캔 대상으로 등록된 공인 IP는 삭제되지 않습니다. 실시간 캡처가 계속 중이면 새 외부 통신은 다시 기록됩니다.",
            "NetLoom · 외부 관찰 이력", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        ClearExternalObservationHistoryCore();
        FooterStatus.Text = "외부/Public 통신 관찰 이력을 지웠습니다.";
        AddEngineTrace("TRAFFIC", "", "external observation history cleared", EngineTraceVerbosity.General);
    }

    private CaptureCoverageSnapshot GetCaptureCoverageSnapshot()
    {
        var raw = _packetCapture.TakeCoverageSnapshot(_settings.ShowLocalExternalTopology);
        if (raw.Mode == _settings.PacketCaptureScope) return raw;
        return new CaptureCoverageSnapshot
        {
            Mode = _settings.PacketCaptureScope,
            IsRunning = false,
            AllowLocalExternalTopology = _settings.ShowLocalExternalTopology
        };
    }

    private void ClearExternalObservationHistoryCore()
    {
        _externalObservationRegistry.Clear();
        _externalObservationSnapshot = _externalObservationRegistry.TakeSnapshot(512, 2048);
        TopologyVisual.SetExternalObservationSnapshot(_externalObservationSnapshot);
        UpdateExternalHistoryUi();
    }

    private void UpdateExternalHistoryUi()
    {
        if (TopologyExternalHistoryClearButton is null) return;
        int count = _externalObservationSnapshot.Count;
        var coverage = GetCaptureCoverageSnapshot();
        var significance = TopologySignificanceService.Build(
            _externalObservationSnapshot,
            GetDisplayedSecuritySnapshot(),
            coverage,
            _settings.ShowLowSignificanceExternalTopology,
            _settings.ExcludeSensorHostTopologyConnections);
        string visibility = count > 0 && !coverage.CanRenderObservedExternalTopology
            ? " · 숨김"
            : count > 0 && coverage.CanRenderObservedExternalTopology
                ? $" · 표시 {significance.RenderedNodeCount:N0}"
                : string.Empty;
        TopologyExternalHistoryClearButton.Content = count > 0 ? $"외부 이력 지우기 ({count:N0}{visibility})" : "외부 이력 지우기";
        TopologyExternalHistoryClearButton.IsEnabled = count > 0;
        if (TopologyCoverageText is not null)
            TopologyCoverageText.ToolTip = $"{coverage.TopologyPolicyText}\n\n관계도 표시 정책: {significance.SummaryText}. 패킷/감사/보안 분석 원본 Flow는 유지됩니다.";
    }

    private void SecurityAnalysisReset_Click(object sender, RoutedEventArgs e)
    {
        if (!_securityRelationshipSnapshot.HasData) return;
        var answer = ThemedMessageBox.Show(
            "현재 캡처 세션의 보안 관계 분석 기준과 위험 점수/이벤트 이력을 초기화하시겠습니까?\n\n외부 관찰 이력은 별도이며 유지됩니다. 캡처가 계속 중이면 이후 패킷부터 다시 분석합니다.",
            "NetLoom · 보안 관계 분석", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;
        ClearSecurityRelationshipAnalysisCore();
        FooterStatus.Text = "보안 관계 분석 이력을 초기화했습니다.";
        AddEngineTrace("SECURITY", "", "relationship security analysis cleared", EngineTraceVerbosity.General);
    }

    private void ClearSecurityRelationshipAnalysisCore()
    {
        _securityRelationshipAnalyzer.Clear();
        _securityRelationshipSnapshot = SecurityRelationshipSnapshot.Empty;
        _securityReplaySnapshot = null;
        _securityTimelineRecorder.Clear();
        TopologyVisual.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
        UpdateSecurityRelationshipUi();
    }

    private SecurityRelationshipSnapshot GetDisplayedSecuritySnapshot() => _securityReplaySnapshot ?? _securityRelationshipSnapshot;

    private void UpdateSecurityRelationshipUi()
    {
        if (TopologySecurityStatusText is null || TopologySecurityResetButton is null) return;
        if (TopologyBaselineResetButton is not null)
            TopologyBaselineResetButton.IsEnabled = _securityRelationshipAnalyzer.BaselineDeviceCount > 0;

        var display = GetDisplayedSecuritySnapshot();
        if (!display.HasData)
        {
            TopologySecurityStatusText.Text = _securityRelationshipAnalyzer.BaselineDeviceCount > 0
                ? $"보안 분석 대기 · Baseline {_securityRelationshipAnalyzer.BaselineDeviceCount:N0}대 학습됨"
                : "보안 분석 대기 · Baseline 학습 대기";
            TopologySecurityStatusText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            TopologySecurityResetButton.IsEnabled = false;
            return;
        }

        string replay = _securityReplaySnapshot is null ? "" : $"REPLAY {display.TimestampUtc.ToLocalTime():HH:mm:ss} · ";
        TopologySecurityStatusText.Text =
            $"{replay}보안 감사 · H {display.HighCount:N0} · M {display.MediumCount:N0} · W {display.WatchCount:N0} · " +
            $"DNS {display.DnsAnomalyNodeCount:N0} · BL {display.BaselineReadyCount:N0}/{display.Nodes.Count:N0} (이탈 {display.BaselineAnomalyCount:N0}) · " +
            $"비콘 {display.BeaconNodeCount:N0} · 횡적 {display.LateralMovementNodeCount:N0}";
        TopologySecurityStatusText.Foreground = new SolidColorBrush(display.HighCount > 0
            ? Color.FromRgb(255, 112, 96)
            : display.MediumCount > 0 ? Color.FromRgb(244, 183, 72)
            : display.WatchCount > 0 ? Color.FromRgb(250, 216, 59)
            : Color.FromRgb(98, 217, 166));
        TopologySecurityResetButton.IsEnabled = _securityRelationshipSnapshot.HasData;
    }

    private void SecurityPolicy_Click(object sender, RoutedEventArgs e)
    {
        var window = new SecurityPolicyWindow(_securityRelationshipAnalyzer) { Owner = this };
        window.ShowDialog();
        _externalIntelligenceService.Reload();
        _externalObservationRegistry.RefreshIntelligence();
        _externalObservationSnapshot = _externalObservationRegistry.TakeSnapshot(512, 2048);
        TopologyVisual.SetExternalObservationSnapshot(_externalObservationSnapshot);
        _securityRelationshipSnapshot = _securityRelationshipAnalyzer.TakeSnapshot(512, 256);
        TopologyVisual.SetSecurityRelationshipSnapshot(GetDisplayedSecuritySnapshot());
        UpdateSecurityRelationshipUi();
        FooterStatus.Text = $"보안 정책 적용 · Offline intelligence {_securityRelationshipAnalyzer.IntelligenceRecordCount:N0} records";
    }

    private void SecurityTimeline_Click(object sender, RoutedEventArgs e)
    {
        var window = new SecurityTimelineWindow(
            () => _securityTimelineRecorder.TakeSnapshot(),
            ApplySecurityReplaySnapshot,
            _securityTimelineRecorder.Clear)
        {
            Owner = this
        };
        window.Show();
    }

    private void ApplySecurityReplaySnapshot(SecurityRelationshipSnapshot? snapshot)
    {
        _securityReplaySnapshot = snapshot;
        TopologyVisual.SetSecurityRelationshipSnapshot(GetDisplayedSecuritySnapshot());
        UpdateSecurityRelationshipUi();
        FooterStatus.Text = snapshot is null
            ? "관계도 보안 표시를 LIVE로 복귀했습니다."
            : $"관계도 보안 REPLAY · {snapshot.TimestampUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · 실제 분석은 계속 LIVE 누적 중";
    }

    private void SecurityBaselineReset_Click(object sender, RoutedEventArgs e)
    {
        var answer = ThemedMessageBox.Show(
            $"장비별 정상 행동 Baseline 학습값 {_securityRelationshipAnalyzer.BaselineDeviceCount:N0}대를 모두 삭제하시겠습니까?\n\n" +
            "현재 관계도 보안 분석 세션과 External 이력은 유지됩니다. 삭제 후 정상 행동을 다시 학습합니다.",
            "NetLoom · Baseline 초기화", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        ClearSecurityBehaviorBaselineCore();
        FooterStatus.Text = "보안 정상 행동 Baseline을 초기화했습니다. 이후 정상 구간부터 다시 학습합니다.";
        AddEngineTrace("SECURITY", "", "behavior baseline cleared", EngineTraceVerbosity.General);
    }

    private void ClearSecurityBehaviorBaselineCore()
    {
        _securityRelationshipAnalyzer.ClearBaseline();
        _securityReplaySnapshot = null;
        _securityRelationshipSnapshot = _securityRelationshipAnalyzer.TakeSnapshot(512, 256);
        TopologyVisual.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
        UpdateSecurityRelationshipUi();
    }

    private void TopologyZoomIn_Click(object sender, RoutedEventArgs e) => ApplyTopologyZoom(_topologyZoom + 0.10);
    private void TopologyExternalDetail_Changed(object sender, RoutedEventArgs e)
    {
        if (_settings is null || TopologyShowAllExternalCheck is null) return;
        bool include = TopologyShowAllExternalCheck.IsChecked == true;
        _settings.ShowLowSignificanceExternalTopology = include;
        TopologyVisual.SetIncludeLowSignificanceExternal(include);
        try { SettingsService.Save(_settings); } catch { }
        FooterStatus.Text = include
            ? "관계도 외부 표시: 저중요 연결까지 포함"
            : "관계도 외부 표시: 중요 Flow 우선 · 저중요 연결 억제";
    }

    private void TopologySensorHostConnections_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncingTopologyDisplayOptions || _settings is null || TopologyExcludeSensorHostConnectionsCheck is null) return;
        ApplySensorHostTopologyExclusion(TopologyExcludeSensorHostConnectionsCheck.IsChecked == true, persist: true, updateStatus: true);
    }

    private void ApplySensorHostTopologyExclusion(bool exclude, bool persist, bool updateStatus)
    {
        if (_settings is null) return;

        _syncingTopologyDisplayOptions = true;
        try
        {
            _settings.ExcludeSensorHostTopologyConnections = exclude;
            if (TopologyExcludeSensorHostConnectionsCheck is not null)
                TopologyExcludeSensorHostConnectionsCheck.IsChecked = exclude;
            TopologyVisual?.SetExcludeSensorHostConnections(exclude);
        }
        finally
        {
            _syncingTopologyDisplayOptions = false;
        }

        if (persist)
        {
            try { SettingsService.Save(_settings); } catch { }
        }

        UpdateExternalHistoryUi();
        if (updateStatus && FooterStatus is not null)
        {
            FooterStatus.Text = exclude
                ? "관계도 표시: NetLoom 실행 PC의 External/Public 연결을 제외합니다. 원본 패킷·보안 분석·감사 데이터는 유지됩니다."
                : "관계도 표시: NetLoom 실행 PC의 의미있는 External/Public 연결도 표시합니다.";
        }
    }

    private void TopologyZoomOut_Click(object sender, RoutedEventArgs e) => ApplyTopologyZoom(_topologyZoom - 0.10);
    private void TopologyZoomReset_Click(object sender, RoutedEventArgs e) => ApplyTopologyZoom(1.00);

    private void TopologyFit_Click(object sender, RoutedEventArgs e)
    {
        TopologyVisual.UpdateLayout();
        double contentWidth = double.IsNaN(TopologyVisual.Width) ? TopologyVisual.ActualWidth : TopologyVisual.Width;
        double contentHeight = double.IsNaN(TopologyVisual.Height) ? TopologyVisual.ActualHeight : TopologyVisual.Height;
        double viewportWidth = Math.Max(1, TopologyScrollViewer.ViewportWidth - 24);
        double viewportHeight = Math.Max(1, TopologyScrollViewer.ViewportHeight - 24);

        if (contentWidth <= 0 || contentHeight <= 0) return;
        double scale = Math.Min(viewportWidth / contentWidth, viewportHeight / contentHeight);
        ApplyTopologyZoom(Math.Clamp(scale * 0.97, 0.25, 1.00));
        TopologyScrollViewer.ScrollToHome();
    }

    private void TopologyPerspective_Click(object sender, RoutedEventArgs e)
    {
        var window = new Topology3DWindow(
            () => _allResults.ToList(),
            GetSelectedGateway,
            GetTopologyRootNetworks,
            () => _nestedNetworks.ToList(),
            () => _trafficSnapshot,
            () => _trafficAuditSnapshot,
            ToggleTrafficAuditAsync,
            OpenTrafficAuditWindow,
            OpenPacketInspectorWindow,
            () => _externalObservationRegistry.TakeSnapshot(512, 2048),
            GetCaptureCoverageSnapshot,
            ClearExternalObservationHistoryCore,
            GetDisplayedSecuritySnapshot,
            ClearSecurityRelationshipAnalysisCore,
            ClearSecurityBehaviorBaselineCore,
            _settings.ShowLowSignificanceExternalTopology,
            _settings.ExcludeSensorHostTopologyConnections,
            exclude => ApplySensorHostTopologyExclusion(exclude, persist: true, updateStatus: false))
        {
            Owner = this
        };
        window.Show();
        FooterStatus.Text = "실제 3D 관계도 열림 · 마우스 드래그로 회전, 휠로 확대/축소";
    }

    private void TopologyScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if ((Keyboard.Modifiers & ModifierKeys.Control) != ModifierKeys.Control) return;
        ApplyTopologyZoom(_topologyZoom + (e.Delta > 0 ? 0.10 : -0.10));
        e.Handled = true;
    }

    private void ApplyTopologyZoom(double zoom)
    {
        _topologyZoom = Math.Clamp(zoom, 0.25, 2.50);
        _topologyScaleTransform.ScaleX = _topologyZoom;
        _topologyScaleTransform.ScaleY = _topologyZoom;
        if (TopologyZoomText is not null)
            TopologyZoomText.Text = $"{_topologyZoom * 100:0}%";
    }

    private void SetViewMode(ViewMode mode)
    {
        _viewMode = mode;
        ListPanel.Visibility = mode == ViewMode.List ? Visibility.Visible : Visibility.Collapsed;
        MatrixPanel.Visibility = mode == ViewMode.Matrix ? Visibility.Visible : Visibility.Collapsed;
        TopologyPanel.Visibility = mode == ViewMode.Topology ? Visibility.Visible : Visibility.Collapsed;

        SetModeButtonState(ListModeButton, mode == ViewMode.List);
        SetModeButtonState(MatrixModeButton, mode == ViewMode.Matrix);
        SetModeButtonState(TopologyModeButton, mode == ViewMode.Topology);
    }

    private static void SetModeButtonState(Button button, bool selected)
    {
        if (selected)
        {
            button.Background = new SolidColorBrush(Color.FromRgb(250, 216, 59));
            button.Foreground = new SolidColorBrush(Color.FromRgb(24, 24, 24));
            button.BorderBrush = new SolidColorBrush(Color.FromRgb(250, 216, 59));
        }
        else
        {
            button.ClearValue(Control.BackgroundProperty);
            button.ClearValue(Control.ForegroundProperty);
            button.ClearValue(Control.BorderBrushProperty);
        }
    }

    private void EngineGeneral_Click(object sender, RoutedEventArgs e) => SetEngineVerbosity(EngineTraceVerbosity.General);
    private void EngineDetailed_Click(object sender, RoutedEventArgs e) => SetEngineVerbosity(EngineTraceVerbosity.Detailed);
    private void EngineRaw_Click(object sender, RoutedEventArgs e) => SetEngineVerbosity(EngineTraceVerbosity.Raw);

    private void SetEngineVerbosity(EngineTraceVerbosity verbosity)
    {
        _engineTraceVerbosity = verbosity;

        SetModeButtonState(EngineGeneralButton, verbosity == EngineTraceVerbosity.General);
        SetModeButtonState(EngineDetailedButton, verbosity == EngineTraceVerbosity.Detailed);
        SetModeButtonState(EngineRawButton, verbosity == EngineTraceVerbosity.Raw);

        RefreshEngineTraceView();

        if (EngineStateText is not null)
        {
            EngineStateText.Text = _scanCts is not null
                ? $"RUNNING · {EngineVerbosityText(verbosity)} trace"
                : $"대기 중 · {EngineVerbosityText(verbosity)} trace";
        }
    }

    private static string EngineVerbosityText(EngineTraceVerbosity verbosity) => verbosity switch
    {
        EngineTraceVerbosity.General => "GENERAL",
        EngineTraceVerbosity.Raw => "RAW",
        _ => "DETAILED"
    };

    private void ClearEngineTrace_Click(object sender, RoutedEventArgs e)
    {
        EngineTraceEntries.Clear();
        _engineTraceHistory.Clear();
        UpdateEngineTraceCount();
    }

    private void AddEngineTrace(EngineTraceEntry entry)
    {
        _engineTraceHistory.Add(entry);
        if (_engineTraceHistory.Count > MaxEngineTraceHistoryEntries)
        {
            int removeCount = Math.Min(1000, _engineTraceHistory.Count - MaxEngineTraceHistoryEntries);
            _engineTraceHistory.RemoveRange(0, removeCount);
        }

        if (entry.Verbosity <= _engineTraceVerbosity)
        {
            EngineTraceEntries.Add(entry);
            while (EngineTraceEntries.Count > MaxEngineTraceEntries)
                EngineTraceEntries.RemoveAt(0);

            if (EngineAutoScrollCheckBox.IsChecked == true)
                EngineTraceList.ScrollIntoView(entry);
        }

        UpdateEngineTraceCount();
    }

    private void RefreshEngineTraceView()
    {
        if (EngineTraceList is null)
            return;

        var filtered = _engineTraceHistory
            .Where(entry => entry.Verbosity <= _engineTraceVerbosity)
            .TakeLast(MaxEngineTraceEntries)
            .ToList();

        EngineTraceEntries.Clear();
        foreach (var entry in filtered)
            EngineTraceEntries.Add(entry);

        UpdateEngineTraceCount();

        if (EngineAutoScrollCheckBox.IsChecked == true && EngineTraceEntries.Count > 0)
            EngineTraceList.ScrollIntoView(EngineTraceEntries[^1]);
    }

    private void UpdateEngineTraceCount()
    {
        if (EngineEntryCountText is null)
            return;

        EngineEntryCountText.Text = _engineTraceHistory.Count == EngineTraceEntries.Count
            ? $"{EngineTraceEntries.Count:N0} lines"
            : $"{EngineTraceEntries.Count:N0} / {_engineTraceHistory.Count:N0}";
    }

    private void AddEngineTrace(string category, string ipAddress, string message, EngineTraceVerbosity verbosity)
    {
        AddEngineTrace(new EngineTraceEntry
        {
            Timestamp = DateTime.Now,
            Category = category,
            IpAddress = ipAddress,
            Message = message,
            Verbosity = verbosity
        });
    }

    private void UpdateEngineStats()
    {
        int active = Math.Max(0, _engineStartedHosts - _engineCompletedHosts);
        int queue = Math.Max(0, _engineTotalHosts - _engineStartedHosts);
        EngineWorkersText.Text = $"{Math.Min(active, _engineConfiguredWorkers):N0} / {_engineConfiguredWorkers:N0}";
        EngineQueueText.Text = queue.ToString("N0", CultureInfo.InvariantCulture);
        EngineOnlineText.Text = _onlineCount.ToString("N0", CultureInfo.InvariantCulture);
    }

    private void ResetEnginePanel()
    {
        if (EngineStatusDot is null) return;
        EngineStatusDot.Fill = new SolidColorBrush(Color.FromRgb(90, 90, 90));
        EngineStateText.Text = $"대기 중 · {EngineVerbosityText(_engineTraceVerbosity)} trace";
        EngineCurrentStageText.Text = "IDLE";
        EngineWorkersText.Text = "0 / 0";
        EngineQueueText.Text = "0";
        EngineRateText.Text = "0.0/s";
        EngineOnlineText.Text = "0";
        UpdateEngineTraceCount();
        SetPipelineNeutral();
    }

    private void SetEngineRunning(bool running, bool completed = false)
    {
        if (EngineStatusDot is null) return;
        if (running)
        {
            EngineStatusDot.Fill = new SolidColorBrush(Color.FromRgb(250, 216, 59));
            EngineStateText.Text = $"RUNNING · {EngineVerbosityText(_engineTraceVerbosity)} trace";
        }
        else if (completed)
        {
            EngineStatusDot.Fill = new SolidColorBrush(Color.FromRgb(98, 217, 166));
            EngineStateText.Text = "COMPLETE · trace retained";
            EngineCurrentStageText.Text = "DONE";
            SetPipelineNeutral();
        }
        else
        {
            EngineStatusDot.Fill = new SolidColorBrush(Color.FromRgb(255, 106, 106));
            EngineStateText.Text = "STOPPED · trace retained";
        }
    }

    private void HighlightPipelineStage(string category)
    {
        if (PipeDiscover is null) return;
        string stage = category.ToUpperInvariant() switch
        {
            "RANGE" or "QUEUE" or "DISCOVER" => "DISCOVER",
            "HOST" or "ICMP" => "PING",
            "TCP" => "PORT",
            "DNS" or "ARP" or "IPP" or "SNMP" or "CLASSIFY" or "ONLINE" or "OFFLINE" => "IDENTIFY",
            "SMB" or "ALERT" => "AUDIT",
            "MAP" => "MAP",
            "REPORT" => "REPORT",
            _ => EngineCurrentStageText.Text
        };

        if (string.IsNullOrWhiteSpace(stage)) return;
        EngineCurrentStageText.Text = stage;
        SetPipelineNeutral();

        var target = stage switch
        {
            "DISCOVER" => PipeDiscover,
            "PING" => PipePing,
            "PORT" => PipePort,
            "IDENTIFY" => PipeIdentify,
            "AUDIT" => PipeAudit,
            "MAP" => PipeMap,
            "REPORT" => PipeReport,
            _ => null
        };

        if (target is not null)
        {
            target.Background = new SolidColorBrush(Color.FromRgb(57, 51, 24));
            target.BorderBrush = new SolidColorBrush(Color.FromRgb(122, 104, 33));
            if (target.Child is TextBlock text)
                text.Foreground = new SolidColorBrush(Color.FromRgb(250, 216, 59));
        }
    }

    private void SetPipelineNeutral()
    {
        foreach (var border in new[] { PipeDiscover, PipePing, PipePort, PipeIdentify, PipeAudit, PipeMap, PipeReport })
        {
            if (border is null) continue;
            border.Background = new SolidColorBrush(Color.FromRgb(32, 32, 32));
            border.BorderBrush = new SolidColorBrush(Color.FromRgb(48, 48, 48));
            if (border.Child is TextBlock text)
                text.Foreground = new SolidColorBrush(Color.FromRgb(132, 132, 132));
        }
    }

    private void StartScanPulse()
    {
        var animation = new DoubleAnimation
        {
            From = 0.25,
            To = 1.0,
            Duration = TimeSpan.FromMilliseconds(520),
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever
        };
        ScanPulse.BeginAnimation(OpacityProperty, animation);
    }

    private void StopScanPulse(bool completed)
    {
        ScanPulse.BeginAnimation(OpacityProperty, null);
        ScanPulse.Opacity = completed ? 0.8 : 0.28;
    }

    private void ExportTopologyPng_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.All(r => !r.IsOnline) && string.IsNullOrWhiteSpace(GetSelectedGateway()))
        {
            ThemedMessageBox.Show("저장할 관계도가 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var outputSize = GetRecommendedTopologyOutputSize();
        int width = (int)Math.Ceiling(outputSize.Width);
        int height = (int)Math.Ceiling(outputSize.Height);
        var topology = CreateTopologyOutputVisual(width, height);
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(topology);

        var dialog = new SaveFileDialog
        {
            Filter = "PNG 이미지 (*.png)|*.png",
            FileName = $"NetLoom_Topology_{DateTime.Now:yyyyMMdd_HHmmss}.png"
        };
        if (dialog.ShowDialog() != true) return;

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(dialog.FileName);
        encoder.Save(stream);
        FooterStatus.Text = _settings.LightTopologyOutput
            ? $"관계도 PNG 저장 완료 (라이트) · {dialog.FileName}"
            : $"관계도 PNG 저장 완료 (다크) · {dialog.FileName}";
    }

    private void PrintTopology_Click(object sender, RoutedEventArgs e)
    {
        if (_allResults.All(r => !r.IsOnline) && string.IsNullOrWhiteSpace(GetSelectedGateway()))
        {
            ThemedMessageBox.Show("인쇄할 관계도가 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new PrintDialog();
        if (dialog.ShowDialog() != true) return;

        double printableWidth = Math.Max(600, dialog.PrintableAreaWidth);
        double printableHeight = Math.Max(400, dialog.PrintableAreaHeight);
        var outputSize = GetRecommendedTopologyOutputSize();
        var topology = CreateTopologyOutputVisual(outputSize.Width, outputSize.Height);

        var viewbox = new Viewbox
        {
            Width = printableWidth,
            Height = printableHeight,
            Stretch = Stretch.Uniform,
            StretchDirection = StretchDirection.DownOnly,
            Child = topology
        };
        viewbox.Measure(new Size(printableWidth, printableHeight));
        viewbox.Arrange(new Rect(0, 0, printableWidth, printableHeight));
        viewbox.UpdateLayout();
        dialog.PrintVisual(viewbox, "NetLoom Network Audit Topology");
        FooterStatus.Text = _settings.LightTopologyOutput
            ? "관계도 인쇄 작업 전송 완료 · 라이트 출력"
            : "관계도 인쇄 작업 전송 완료 · 다크 출력";
    }

    private async void WifiAudit_Click(object sender, RoutedEventArgs e)
    {
        if (_scanCts is not null)
        {
            ThemedMessageBox.Show("네트워크 스캔이 끝난 뒤 Wi-Fi 보안 점검을 실행하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (AdapterCombo.SelectedItem is not AdapterInfo adapter || !adapter.IsWireless)
        {
            ThemedMessageBox.Show("Wi-Fi 어댑터를 선택해야 무선 보안 점검을 실행할 수 있습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        WifiAuditButton.IsEnabled = false;
        WifiAuditButton.Content = "Wi-Fi 점검 중…";
        WifiAuditHintText.Text = "Windows WLAN API로 주변 SSID와 인증/암호화 방식을 확인하고 있습니다.";
        FooterStatus.Text = "Wi-Fi 보안 점검 중";
        AddEngineTrace("WIFI", adapter.Address, "wireless security audit start", EngineTraceVerbosity.General);

        try
        {
            var audit = await WifiAuditService.AuditAsync(adapter);
            _lastWifiAudit = audit;

            if (!audit.Supported)
            {
                WifiAuditHintText.Text = audit.StatusMessage;
                FooterStatus.Text = "Wi-Fi 보안 점검 실패";
                AddEngineTrace("WIFI", adapter.Address, audit.StatusMessage, EngineTraceVerbosity.General);
                ThemedMessageBox.Show(audit.StatusMessage, "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            WifiAuditHintText.Text = $"마지막 점검 {audit.AuditedAt:HH:mm:ss} · SSID {audit.Networks.Count:N0}개 · HIGH {audit.HighCount:N0} / MED {audit.MediumCount:N0}";
            FooterStatus.Text = $"Wi-Fi 보안 점검 완료 · SSID {audit.Networks.Count:N0}개";
            AddEngineTrace("WIFI", adapter.Address, $"done · SSID {audit.Networks.Count} · HIGH {audit.HighCount} · MED {audit.MediumCount}", EngineTraceVerbosity.General);

            var window = new WifiAuditWindow(audit) { Owner = this };
            window.ShowDialog();
        }
        catch (Exception ex)
        {
            string logPath = CrashLogService.Write("WifiAuditWindow", ex);
            string rootMessage = ex.GetBaseException().Message;
            FooterStatus.Text = "Wi-Fi 보안 점검 오류 · 로그 저장됨";
            WifiAuditHintText.Text = rootMessage;
            AddEngineTrace("WIFI", adapter.Address, $"error · {rootMessage}", EngineTraceVerbosity.General);
            ThemedMessageBox.Show(
                $"Wi-Fi 보안 점검 중 오류가 발생했습니다.\n\n{rootMessage}\n\n로그: {logPath}",
                "NetLoom",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            UpdateWifiAuditAvailability();
        }
    }

    private void UpdateWifiAuditAvailability()
    {
        if (WifiAuditButton is null || WifiAuditHintText is null)
            return;

        if (AdapterCombo.SelectedItem is AdapterInfo adapter && adapter.IsWireless)
        {
            WifiAuditButton.IsEnabled = _scanCts is null;
            WifiAuditButton.Content = "Wi-Fi 보안 점검";
            if (_lastWifiAudit is null || !string.Equals(_lastWifiAudit.InterfaceId, adapter.InterfaceId, StringComparison.OrdinalIgnoreCase))
                WifiAuditHintText.Text = "주변 SSID의 Open/WEP/WPA/TKIP/WPA2/WPA3 보안 상태를 점검합니다.";
        }
        else
        {
            WifiAuditButton.IsEnabled = false;
            WifiAuditButton.Content = "Wi-Fi 보안 점검";
            WifiAuditHintText.Text = "Wi-Fi 어댑터를 선택하면 무선 보안 점검을 사용할 수 있습니다.";
        }
    }

    private void RefreshAdapters_Click(object sender, RoutedEventArgs e)
    {
        LoadAdapters();
    }

    private async void AdapterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (AdapterCombo.SelectedItem is AdapterInfo adapter)
        {
            if (_packetCapture.IsRunning && !string.Equals(_packetCapture.AdapterAddress, adapter.Address, StringComparison.OrdinalIgnoreCase))
            {
                if (_trafficAuditRecorder.IsRecording)
                    await StopTrafficAuditAsync("어댑터 변경");
                _packetCapture.Stop();
                _trafficTracker.Clear();
                _trafficSnapshot = TrafficSnapshot.Empty;
                TopologyVisual.SetTrafficSnapshot(_trafficSnapshot);
                _securityRelationshipAnalyzer.Clear();
                _securityRelationshipSnapshot = SecurityRelationshipSnapshot.Empty;
                _securityReplaySnapshot = null;
                _securityTimelineRecorder.Clear();
                TopologyVisual.SetSecurityRelationshipSnapshot(_securityRelationshipSnapshot);
                UpdateSecurityRelationshipUi();
                AddEngineTrace("TRAFFIC", adapter.Address, "adapter changed · packet capture stopped", EngineTraceVerbosity.General);
            }

            CidrTextBox.Text = BuildNetworkCidr(adapter.Address, adapter.PrefixLength);
            FooterStatus.Text = string.IsNullOrWhiteSpace(adapter.GatewayAddress)
                ? $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength}"
                : $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength} · GW {adapter.GatewayAddress}";
            if (_lastWifiAudit is not null && !string.Equals(_lastWifiAudit.InterfaceId, adapter.InterfaceId, StringComparison.OrdinalIgnoreCase))
                _lastWifiAudit = null;
            RefreshScopeRecommendations(adapter);
            UpdateWifiAuditAvailability();
        }
    }

    private void PortsTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateSelectedPortCount();
    }

    private void UpdateSelectedPortCount()
    {
        if (SelectedPortCountText is null || PortsTextBox is null) return;
        try
        {
            SelectedPortCountText.Text = $"{ParsePorts(PortsTextBox.Text).Count:N0}개";
            SelectedPortCountText.Foreground = new SolidColorBrush(Color.FromRgb(119, 119, 119));
        }
        catch
        {
            SelectedPortCountText.Text = "확인 필요";
            SelectedPortCountText.Foreground = new SolidColorBrush(Color.FromRgb(255, 106, 106));
        }
    }

    private Dictionary<string, string> BuildAuditGroupGatewayLookup(
        IReadOnlyList<ScanTargetGroupDefinition> groups,
        AdapterInfo? selectedAdapter)
    {
        var roots = ResolveTopologyRootNetworks(groups, selectedAdapter);
        return roots
            .Where(r => !string.IsNullOrWhiteSpace(r.GroupLabel))
            .GroupBy(r => r.GroupLabel, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().GatewayAddress, StringComparer.OrdinalIgnoreCase);
    }

    private IReadOnlyList<TopologyRootNetwork> GetTopologyRootNetworks()
    {
        return ResolveTopologyRootNetworks(_lastTargetGroups, AdapterCombo.SelectedItem as AdapterInfo);
    }

    private IReadOnlyList<TopologyRootNetwork> ResolveTopologyRootNetworks(
        IReadOnlyList<ScanTargetGroupDefinition> groups,
        AdapterInfo? selectedAdapter)
    {
        if (groups.Count == 0) return Array.Empty<TopologyRootNetwork>();

        IReadOnlyList<AdapterInfo> adapters;
        try { adapters = NetworkAdapterService.GetAdapters(); }
        catch { adapters = Array.Empty<AdapterInfo>(); }

        IReadOnlyList<SubnetRecommendation> recommendations = Array.Empty<SubnetRecommendation>();
        if (selectedAdapter is not null)
        {
            try { recommendations = NetworkScopeDiscoveryService.GetRecommendations(selectedAdapter); }
            catch { }
        }

        var roots = new List<TopologyRootNetwork>();
        foreach (var group in groups)
        {
            string gateway = "";
            string iface = "";
            string source = "감사 범위";
            bool isDirect = false;

            var recommendation = recommendations.FirstOrDefault(r =>
                string.Equals(r.Cidr, group.Expression, StringComparison.OrdinalIgnoreCase));
            if (recommendation is not null)
            {
                gateway = IsIpv4(recommendation.Gateway) ? recommendation.Gateway : "";
                iface = recommendation.InterfaceAddress;
                source = recommendation.Source;
                isDirect = string.Equals(recommendation.Source, "직접 연결", StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(recommendation.Source, "다른 활성 어댑터", StringComparison.OrdinalIgnoreCase) ||
                           string.Equals(recommendation.Source, "활성 인터페이스", StringComparison.OrdinalIgnoreCase);
            }

            AdapterInfo? directAdapter = adapters.FirstOrDefault(a =>
                string.Equals(BuildNetworkCidr(a.Address, a.PrefixLength), group.Expression, StringComparison.OrdinalIgnoreCase));
            directAdapter ??= adapters.FirstOrDefault(a =>
                !string.IsNullOrWhiteSpace(a.GatewayAddress) &&
                group.Hosts.Any(ip => string.Equals(ip.ToString(), a.GatewayAddress, StringComparison.OrdinalIgnoreCase)));

            if (directAdapter is not null)
            {
                gateway = directAdapter.GatewayAddress;
                iface = directAdapter.Address;
                source = string.Equals(directAdapter.Address, selectedAdapter?.Address, StringComparison.OrdinalIgnoreCase)
                    ? "직접 연결"
                    : "다른 활성 어댑터";
                isDirect = true;
            }
            else if (string.IsNullOrWhiteSpace(gateway) && selectedAdapter is not null &&
                     !string.IsNullOrWhiteSpace(selectedAdapter.GatewayAddress) &&
                     group.Hosts.Any(ip => string.Equals(ip.ToString(), selectedAdapter.GatewayAddress, StringComparison.OrdinalIgnoreCase)))
            {
                gateway = selectedAdapter.GatewayAddress;
                iface = selectedAdapter.Address;
                source = "직접 연결";
                isDirect = true;
            }

            roots.Add(new TopologyRootNetwork
            {
                GroupLabel = group.GroupLabel,
                Expression = group.Expression,
                GatewayAddress = gateway,
                InterfaceAddress = iface,
                Source = source,
                IsDirect = isDirect
            });
        }
        return roots;
    }

    private static bool IsIpv4(string value) =>
        IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork;

    private string GetSelectedGateway() => (AdapterCombo.SelectedItem as AdapterInfo)?.GatewayAddress ?? "";

    private static string BuildNetworkCidr(string address, int prefixLength)
    {
        var ip = IPAddress.Parse(address);
        var bytes = ip.GetAddressBytes();
        uint value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        uint network = value & mask;

        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefixLength}";
    }


    private static IReadOnlyCollection<int> ParsePorts(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<int>();

        var result = new SortedSet<int>();

        foreach (var token in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var port) ||
                port < 1 || port > 65535)
            {
                throw new ArgumentException($"유효하지 않은 포트: {token}");
            }

            result.Add(port);
        }

        if (result.Count > 64)
            throw new ArgumentException("한 번에 입력할 수 있는 TCP 포트는 최대 64개입니다.");

        return result.ToArray();
    }

    private static int ParseBoundedInt(string text, int min, int max, string label)
    {
        if (!int.TryParse(text, out var value) || value < min || value > max)
            throw new ArgumentException($"{label}은(는) {min:N0}~{max:N0} 범위로 입력하세요.");

        return value;
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private enum ViewMode
    {
        List,
        Matrix,
        Topology
    }
}
