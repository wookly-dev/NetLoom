using System.Globalization;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Media3D;
using System.Windows.Shapes;
using System.Windows.Threading;
using NetLoom.App.Helpers;
using NetLoom.App.Models;
using NetLoom.App.Services;

namespace NetLoom.App.Windows;

public partial class Topology3DWindow : Window
{
    private sealed record NodeInfo(
        DeviceType Type,
        string Ip,
        string Host,
        string Group,
        bool IsSynthetic = false,
        ScanResult? Result = null);

    private sealed class LabelVisual
    {
        public Point3D Position { get; set; }
        public required NodeInfo Info { get; init; }
        public required Border Element { get; init; }
        public TextBlock? ActivityText { get; init; }
        public bool Important { get; init; }
    }

    private sealed class OrbitNode
    {
        public required NodeInfo Info { get; init; }
        public required TranslateTransform3D Translation { get; init; }
        public required LabelVisual Label { get; init; }
        public double SemiMajorAxis { get; init; }
        public double Eccentricity { get; init; }
        public double Inclination { get; init; }
        public double AscendingNode { get; init; }
        public double CurrentAngle { get; set; }
        public double BaseAngularSpeed { get; init; }
        public double CurrentAngularSpeed { get; set; }
        public bool Animated { get; init; }
        public bool IsSatellite { get; init; }
        public OrbitNode? Parent { get; init; }
        public double SatelliteRadius { get; init; }
        public Point3D OrbitCenter { get; init; }
        public Point3D Position { get; set; }
    }

    private sealed class SatelliteRingVisual
    {
        public required OrbitNode Parent { get; init; }
        public required TranslateTransform3D Translation { get; init; }
        public required SolidColorBrush Brush { get; init; }
    }

    private sealed class GatewayHaloVisual
    {
        public required ScaleTransform3D Scale { get; init; }
        public required SolidColorBrush Brush { get; init; }
    }

    private sealed record OrbitMotionState(double CurrentAngle, double CurrentAngularSpeed);

    private sealed record SceneViewState(
        double Yaw,
        double Pitch,
        double Distance,
        double TargetDistance,
        Point3D Target,
        double YawVelocity,
        double PitchVelocity,
        Vector3D PanVelocity,
        double MotionSpeedFactor,
        string? SelectedNodeKey);

    private enum OrbitBand
    {
        Infrastructure,
        Special,
        Peripheral,
        Endpoint,
        Other,
        External
    }

    private enum LabelMode
    {
        Auto,
        Major,
        All
    }

    private readonly List<ScanResult> _results = new();
    private string _gatewayAddress = string.Empty;
    private readonly Func<IEnumerable<ScanResult>>? _resultsProvider;
    private readonly Func<string>? _gatewayProvider;
    private readonly Func<IEnumerable<TopologyRootNetwork>>? _rootProvider;
    private readonly Func<IEnumerable<NestedNetworkInfo>>? _nestedProvider;
    private readonly Func<TrafficSnapshot>? _trafficProvider;
    private readonly Func<TrafficAuditSessionSnapshot>? _trafficAuditProvider;
    private readonly Func<Task>? _trafficAuditToggle;
    private readonly Action? _trafficAuditOpen;
    private readonly Action<string?>? _packetInspectorOpen;
    private readonly Func<ExternalObservationSnapshot>? _externalObservationProvider;
    private readonly Func<CaptureCoverageSnapshot>? _captureCoverageProvider;
    private readonly Action? _externalObservationClear;
    private readonly Func<SecurityRelationshipSnapshot>? _securityRelationshipProvider;
    private readonly Action? _securityRelationshipClear;
    private readonly Action? _securityBaselineClear;
    private readonly List<TopologyRootNetwork> _topologyRoots = new();
    private readonly List<NestedNetworkInfo> _nestedNetworks = new();
    private TrafficSnapshot _trafficSnapshot = TrafficSnapshot.Empty;
    private TrafficAuditSessionSnapshot _trafficAuditSnapshot = TrafficAuditSessionSnapshot.Empty;
    private ExternalObservationSnapshot _externalObservationSnapshot = ExternalObservationSnapshot.Empty;
    private CaptureCoverageSnapshot _captureCoverageSnapshot = CaptureCoverageSnapshot.Empty;
    private SecurityRelationshipSnapshot _securityRelationshipSnapshot = SecurityRelationshipSnapshot.Empty;
    private TopologySignificanceSnapshot _topologySignificanceSnapshot = TopologySignificanceSnapshot.Empty;
    private bool _includeLowSignificanceExternal;
    private bool _excludeSensorHostConnections;
    private readonly Action<bool>? _sensorHostExclusionChanged;
    private readonly Dictionary<Model3D, NodeInfo> _modelInfo = new();
    private readonly Dictionary<string, SolidColorBrush> _trafficGlowByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SolidColorBrush> _auditGlowByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SolidColorBrush> _securityGlowByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, OrbitNode> _orbitNodeByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(GeometryModel3D Model, NodeInfo Info)> _nodeVisuals = new();
    private readonly List<(GeometryModel3D Model, OrbitBand Band, SolidColorBrush Brush)> _orbitRingVisuals = new();
    private readonly List<LabelVisual> _labels = new();
    private readonly List<OrbitNode> _orbitNodes = new();
    private readonly List<SatelliteRingVisual> _satelliteRings = new();
    private readonly HashSet<string> _relatedIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<TopologyCategory> _highlightedCategories = new();
    private readonly PerspectiveCamera _camera = new();
    private readonly DispatcherTimer _orbitTimer;

    private Point _lastMouse;
    private bool _dragging;
    private bool _panning;
    private double _dragDistance;
    private double _yaw = -42;
    private double _pitch = 24;
    private double _distance = 32;
    private double _targetDistance = 32;
    private double _yawVelocity;
    private double _pitchVelocity;
    private Vector3D _panVelocity;
    private DateTime _lastMouseInput = DateTime.UtcNow;
    private Point3D _target = new(0, 0, 0);
    private LabelMode _labelMode = LabelMode.Auto;
    private bool _deviceDetailOpen;
    private NodeInfo? _selectedInfo;
    private NodeInfo? _pressedInfo;
    private Point3D? _pendingOrbitPivot;
    private bool _orbitPivotApplied;
    private bool _orbitMotionEnabled = true;
    private bool _hideIsolated;
    private double _speedPreset = 1.0;
    private double _motionSpeedFactor;
    private DateTime _lastOrbitTick = DateTime.UtcNow;
    private readonly List<GatewayHaloVisual> _gatewayHalos = new();
    private double _sceneRadius = 22;
    private long _sceneExternalNodeSetVersion = -1;
    private string _sceneExternalSignature = "";
    private bool _sceneExternalVisibilityEnabled;
    private bool _externalSceneRefreshQueued;
    private DateTime _lastExternalSceneRefreshUtc = DateTime.MinValue;

    public Topology3DWindow(IEnumerable<ScanResult> results, string gatewayAddress)
        : this(() => results, () => gatewayAddress)
    {
    }

    public Topology3DWindow(
        Func<IEnumerable<ScanResult>> resultsProvider,
        Func<string> gatewayProvider,
        Func<IEnumerable<TopologyRootNetwork>>? rootProvider = null,
        Func<IEnumerable<NestedNetworkInfo>>? nestedProvider = null,
        Func<TrafficSnapshot>? trafficProvider = null,
        Func<TrafficAuditSessionSnapshot>? trafficAuditProvider = null,
        Func<Task>? trafficAuditToggle = null,
        Action? trafficAuditOpen = null,
        Action<string?>? packetInspectorOpen = null,
        Func<ExternalObservationSnapshot>? externalObservationProvider = null,
        Func<CaptureCoverageSnapshot>? captureCoverageProvider = null,
        Action? externalObservationClear = null,
        Func<SecurityRelationshipSnapshot>? securityRelationshipProvider = null,
        Action? securityRelationshipClear = null,
        Action? securityBaselineClear = null,
        bool includeLowSignificanceExternal = false,
        bool excludeSensorHostConnections = false,
        Action<bool>? sensorHostExclusionChanged = null)
    {
        InitializeComponent();
        WindowSizingHelper.EnableWorkAreaMaximize(this);
        _resultsProvider = resultsProvider;
        _gatewayProvider = gatewayProvider;
        _rootProvider = rootProvider;
        _nestedProvider = nestedProvider;
        _trafficProvider = trafficProvider;
        _trafficAuditProvider = trafficAuditProvider;
        _trafficAuditToggle = trafficAuditToggle;
        _trafficAuditOpen = trafficAuditOpen;
        _packetInspectorOpen = packetInspectorOpen;
        _externalObservationProvider = externalObservationProvider;
        _captureCoverageProvider = captureCoverageProvider;
        _externalObservationClear = externalObservationClear;
        _securityRelationshipProvider = securityRelationshipProvider;
        _securityRelationshipClear = securityRelationshipClear;
        _securityBaselineClear = securityBaselineClear;
        _includeLowSignificanceExternal = includeLowSignificanceExternal;
        _excludeSensorHostConnections = excludeSensorHostConnections;
        _sensorHostExclusionChanged = sensorHostExclusionChanged;
        ExternalIncludeLowSignificanceCheck.IsChecked = includeLowSignificanceExternal;
        ExternalExcludeSensorHostConnectionsCheck.IsChecked = excludeSensorHostConnections;
        ReloadResults();
        TopologyViewport.Camera = _camera;

        _orbitTimer = new DispatcherTimer(DispatcherPriority.Render)
        {
            Interval = TimeSpan.FromMilliseconds(16)
        };
        _orbitTimer.Tick += OrbitTimer_Tick;

        Loaded += (_, _) =>
        {
            BuildStarfield();
            BuildScene();
        };
        Closed += (_, _) => _orbitTimer.Stop();
    }

    private void ReloadResults()
    {
        _results.Clear();
        if (_resultsProvider is not null)
            _results.AddRange(_resultsProvider().Where(r => r.IsOnline).OrderBy(r => r.AuditGroupLabel).ThenBy(r => r.IpSortKey));
        _gatewayAddress = _gatewayProvider?.Invoke() ?? _gatewayAddress;
        _topologyRoots.Clear();
        if (_rootProvider is not null)
            _topologyRoots.AddRange(_rootProvider());
        _nestedNetworks.Clear();
        if (_nestedProvider is not null)
            _nestedNetworks.AddRange(_nestedProvider());
        _trafficSnapshot = _trafficProvider?.Invoke() ?? _trafficSnapshot;
        _trafficAuditSnapshot = _trafficAuditProvider?.Invoke() ?? _trafficAuditSnapshot;
        _externalObservationSnapshot = _externalObservationProvider?.Invoke() ?? _externalObservationSnapshot;
        _captureCoverageSnapshot = _captureCoverageProvider?.Invoke() ?? _captureCoverageSnapshot;
        _securityRelationshipSnapshot = _securityRelationshipProvider?.Invoke() ?? _securityRelationshipSnapshot;
        RebuildTopologySignificance();
    }

    private void RebuildTopologySignificance()
    {
        _topologySignificanceSnapshot = TopologySignificanceService.Build(
            _externalObservationSnapshot,
            _securityRelationshipSnapshot,
            _captureCoverageSnapshot,
            _includeLowSignificanceExternal,
            _excludeSensorHostConnections);
    }

    private void BuildScene(bool resetView = true)
    {
        // External/Public node discovery can rebuild the 3D scene while the window stays open.
        // Preserve both the camera pose and the current orbital phase so an automatic refresh
        // does not look like the topology or viewpoint jumped back to its initial position.
        var preservedOrbitState = resetView ? null : CaptureOrbitMotionState();
        var preservedViewState = resetView ? null : CaptureSceneViewState();

        TopologyViewport.Children.Clear();
        LabelCanvas.Children.Clear();
        TrafficOverlayCanvas.Children.Clear();
        _modelInfo.Clear();
        _trafficGlowByIp.Clear();
        _auditGlowByIp.Clear();
        _securityGlowByIp.Clear();
        _orbitNodeByIp.Clear();
        _nodeVisuals.Clear();
        _orbitRingVisuals.Clear();
        _labels.Clear();
        _orbitNodes.Clear();
        _satelliteRings.Clear();
        _relatedIps.Clear();
        _gatewayHalos.Clear();
        _selectedInfo = null;
        _pressedInfo = null;
        if (resetView)
            _motionSpeedFactor = 0;
        _lastOrbitTick = DateTime.UtcNow;

        var lightGroup = new Model3DGroup();
        lightGroup.Children.Add(new AmbientLight(Color.FromRgb(48, 50, 58)));
        lightGroup.Children.Add(new DirectionalLight(Color.FromRgb(222, 228, 244), new Vector3D(-0.35, -0.85, -0.55)));
        lightGroup.Children.Add(new DirectionalLight(Color.FromRgb(86, 96, 120), new Vector3D(0.75, 0.35, 0.60)));
        TopologyViewport.Children.Add(new ModelVisual3D { Content = lightGroup });

        var publicNodes = _results.Where(r => IsPublicIpv4(r.IpAddress)).ToList();
        var local = _results.Where(r => !IsPublicIpv4(r.IpAddress)).ToList();
        var groups = local
            .GroupBy(r => string.IsNullOrWhiteSpace(r.AuditGroupLabel) ? "감사 대역" : r.AuditGroupLabel)
            .OrderBy(g => g.Key, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        var nestedGroupRelations = groups
            .Select(g => new { Group = g, Relation = FindNestedRelationForGroup(g) })
            .ToList();
        var rootGroups = nestedGroupRelations
            .Where(x => x.Relation is null || ResolveRootForGroup(x.Group.Key, x.Group.FirstOrDefault()?.AuditGroupExpression ?? "") is { IsDirect: true })
            .Select(x => x.Group)
            .ToList();

        // Top-level directly attached audit ranges become independent stellar systems.
        // Groups sharing the same confirmed gateway share one star; manually split ranges therefore
        // do not create duplicate stars, while Ethernet/Wi-Fi ranges with different gateways do.
        var rootSystemBuilders = new List<(string Key, string Gateway, List<IGrouping<string, ScanResult>> Groups)>();
        foreach (var group in rootGroups)
        {
            var root = ResolveRootForGroup(group.Key, group.FirstOrDefault()?.AuditGroupExpression ?? "");
            string gateway = root?.GatewayAddress ?? group.Select(r => r.AuditGatewayAddress).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";
            if (string.IsNullOrWhiteSpace(gateway) && rootGroups.Count == 1)
                gateway = _gatewayAddress;
            string key = !string.IsNullOrWhiteSpace(gateway) ? $"GW:{gateway}" : $"GROUP:{group.Key}";
            int existing = rootSystemBuilders.FindIndex(x => string.Equals(x.Key, key, StringComparison.OrdinalIgnoreCase));
            if (existing >= 0)
            {
                rootSystemBuilders[existing].Groups.Add(group);
            }
            else
            {
                rootSystemBuilders.Add((key, gateway, new List<IGrouping<string, ScanResult>> { group }));
            }
        }

        if (rootSystemBuilders.Count == 0 && !string.IsNullOrWhiteSpace(_gatewayAddress))
            rootSystemBuilders.Add(($"GW:{_gatewayAddress}", _gatewayAddress, new List<IGrouping<string, ScanResult>>()));

        double spread = RootSystemSpread(rootSystemBuilders.Count);
        _sceneRadius = Math.Max(22, spread + 18.5);
        var rootGatewayIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int systemIndex = 0; systemIndex < rootSystemBuilders.Count; systemIndex++)
        {
            var system = rootSystemBuilders[systemIndex];
            var center = RootSystemCenter(systemIndex, rootSystemBuilders.Count, spread);
            if (!string.IsNullOrWhiteSpace(system.Gateway)) rootGatewayIps.Add(system.Gateway);

            var gatewayResult = !string.IsNullOrWhiteSpace(system.Gateway)
                ? _results.FirstOrDefault(r => string.Equals(r.IpAddress, system.Gateway, StringComparison.OrdinalIgnoreCase))
                : null;
            string fallbackLabel = system.Groups.Count > 0 ? string.Join(" / ", system.Groups.Select(g => g.Key)) : "Gateway";
            DeviceType gatewayVisualType = gatewayResult is { DeviceType: DeviceType.Router or DeviceType.Firewall }
                ? gatewayResult.DeviceType
                : DeviceType.Router;
            var gatewayInfo = gatewayResult is not null
                ? new NodeInfo(gatewayVisualType, gatewayResult.IpAddress, gatewayResult.HostName, gatewayResult.AuditGroupLabel, false, gatewayResult)
                : new NodeInfo(DeviceType.Router,
                    string.IsNullOrWhiteSpace(system.Gateway) ? fallbackLabel : system.Gateway,
                    string.IsNullOrWhiteSpace(system.Gateway) ? "감사 대역 중심" : "Gateway",
                    fallbackLabel,
                    true);

            AddRootStarNode(center, gatewayInfo, 0.86, Color.FromRgb(250, 216, 59));
            AddGatewayHalo(center);
            lightGroup.Children.Add(new PointLight(Color.FromRgb(255, 230, 126), center)
            {
                Range = 28,
                ConstantAttenuation = 0.8,
                LinearAttenuation = 0.052,
                QuadraticAttenuation = 0.003
            });

            int localGroupIndex = 0;
            foreach (var group in system.Groups)
            {
                var items = group
                    .Where(r => string.IsNullOrWhiteSpace(system.Gateway) || !string.Equals(r.IpAddress, system.Gateway, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                BuildRootGroupOrbits(items, center, systemIndex * 3 + localGroupIndex, localGroupIndex);
                localGroupIndex++;
            }
        }

        // Nested router systems are attached to the actual router/star that advertised the child network.
        int nestedSystemIndex = 0;
        var materializedNestedCidrs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pendingNestedGroups = nestedGroupRelations
            .Where(x => x.Relation is not null && !rootGroups.Contains(x.Group))
            .ToList();
        for (int pass = 0; pass < 12 && pendingNestedGroups.Count > 0; pass++)
        {
            bool progressed = false;
            foreach (var item in pendingNestedGroups.ToArray())
            {
                if (!_orbitNodeByIp.ContainsKey(item.Relation!.ParentIp)) continue;
                if (BuildNestedSubnetSystem(item.Group.ToList(), item.Relation!, nestedSystemIndex++))
                {
                    materializedNestedCidrs.Add(item.Relation!.Cidr);
                    pendingNestedGroups.Remove(item);
                    progressed = true;
                }
            }
            if (!progressed) break;
        }

        var pendingMarkers = _nestedNetworks
            .Where(n => !materializedNestedCidrs.Contains(n.Cidr))
            .ToList();
        for (int pass = 0; pass < 12 && pendingMarkers.Count > 0; pass++)
        {
            bool progressed = false;
            foreach (var nested in pendingMarkers.ToArray())
            {
                if (!_orbitNodeByIp.TryGetValue(nested.ParentIp, out var parentNode)) continue;
                AddNestedSubnetMarker(parentNode, nested, nestedSystemIndex++);
                pendingMarkers.Remove(nested);
                progressed = true;
            }
            if (!progressed) break;
        }

        // External/public planets use a shell around all root systems rather than belonging to one arbitrary gateway.
        if (publicNodes.Count > 0)
        {
            const int nodesPerLane = 16;
            int laneCount = (int)Math.Ceiling(publicNodes.Count / (double)nodesPerLane);
            for (int lane = 0; lane < laneCount; lane++)
            {
                double radius = _sceneRadius + 3.5 + lane * 1.25;
                double inclination = Degrees(-31 + lane * 6);
                double ascendingNode = Degrees(65 + lane * 23);
                double eccentricity = 0.11 + Math.Min(0.04, lane * 0.01);
                AddOrbitRing(radius, inclination, ascendingNode, eccentricity, OrbitColor(OrbitBand.External), OrbitBand.External, new Point3D());

                var laneItems = publicNodes.Skip(lane * nodesPerLane).Take(nodesPerLane).ToList();
                for (int i = 0; i < laneItems.Count; i++)
                {
                    var r = laneItems[i];
                    double angle = -Math.PI / 2 + ((i + 0.5) / Math.Max(1.0, laneItems.Count)) * Math.PI * 2;
                    AddOrbitNode(
                        new NodeInfo(r.DeviceType, r.IpAddress, r.HostName, r.AuditGroupLabel, false, r),
                        radius, angle, inclination, ascendingNode, eccentricity,
                        0.29, NodeColorFor(r.DeviceType, OrbitBand.External), -0.034, true, new Point3D());
                }
            }
        }

        var knownIps = _results.Select(r => r.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var observedExternal = _topologySignificanceSnapshot.ExternalNodes
            .Where(d => IsPublicIpv4(d.Node.IpAddress) && !knownIps.Contains(d.Node.IpAddress))
            .OrderByDescending(d => d.ForceVisible)
            .ThenByDescending(d => d.Score)
            .ThenByDescending(d => d.Node.Bytes)
            .ToList();

        if (observedExternal.Count > 0)
        {
            const int nodesPerLane = 16;
            int baseLane = Math.Max(0, (int)Math.Ceiling(publicNodes.Count / 16d));
            int laneCount = (int)Math.Ceiling(observedExternal.Count / (double)nodesPerLane);
            for (int lane = 0; lane < laneCount; lane++)
            {
                double radius = _sceneRadius + 5.4 + (baseLane + lane) * 1.25;
                double inclination = Degrees(34 + lane * 5);
                double ascendingNode = Degrees(112 + lane * 21);
                double eccentricity = Math.Min(0.18, 0.13 + lane * 0.008);
                AddOrbitRing(radius, inclination, ascendingNode, eccentricity, OrbitColor(OrbitBand.External), OrbitBand.External, new Point3D());

                var laneItems = observedExternal.Skip(lane * nodesPerLane).Take(nodesPerLane).ToList();
                for (int i = 0; i < laneItems.Count; i++)
                {
                    var decision = laneItems[i];
                    var item = decision.Node;
                    double angle = -Math.PI / 2 + ((i + 0.5) / Math.Max(1.0, laneItems.Count)) * Math.PI * 2;
                    string hostLabel = string.IsNullOrWhiteSpace(item.ObservedHost)
                        ? $"{item.ServiceGroup} · 중요도 {decision.Score}"
                        : $"{item.ServiceGroup} · {item.ObservedHost}";
                    string groupLabel = decision.ForceVisible
                        ? $"SECURITY PRIORITY · {decision.Reason}"
                        : string.IsNullOrWhiteSpace(item.IntelligenceText)
                            ? $"Significant Flow · {decision.Reason}"
                            : $"External · {item.IntelligenceText} · {decision.Reason}";
                    AddOrbitNode(
                        new NodeInfo(DeviceType.Internet, item.IpAddress, hostLabel, groupLabel, false, null),
                        radius, angle, inclination, ascendingNode, eccentricity,
                        decision.ForceVisible ? 0.31 : 0.27,
                        decision.ForceVisible ? Color.FromRgb(244, 183, 72) : NodeColorFor(DeviceType.Internet, OrbitBand.External),
                        -0.028 * (1.0 + (i % 3) * 0.025), true, new Point3D());
                }
                _sceneRadius = Math.Max(_sceneRadius, radius + 1.0);
            }
        }

        if (preservedOrbitState is not null)
            RestoreOrbitMotionState(preservedOrbitState);

        RebuildRelationshipIndex();
        UpdateLabelModeButton();
        UpdateOrbitButton();
        SyncSpeedControls();
        ApplyVisualFilters();
        StatusText.Text = $"3D 행성형 관계도 · 항성 {rootSystemBuilders.Count:N0}개 · ONLINE {_results.Count:N0}개 · 감사 대역 {groups.Count:N0}개 · 외부 중요 {_topologySignificanceSnapshot.RenderedNodeCount:N0}/{_topologySignificanceSnapshot.ObservedNodeCount:N0} · {_captureCoverageSnapshot.ModeText}";
        _sceneExternalNodeSetVersion = _externalObservationSnapshot.NodeSetVersion;
        _sceneExternalSignature = _topologySignificanceSnapshot.Signature;
        _sceneExternalVisibilityEnabled = _captureCoverageSnapshot.CanRenderObservedExternalTopology;
        UpdateExternalHistoryUi();
        UpdateCaptureCoverageUi();
        if (resetView)
        {
            ResetCamera();
        }
        else
        {
            RestoreSceneViewState(preservedViewState);
            UpdateCamera();
        }
        UpdateOrbitMotion(0);
        _orbitTimer.Start();
        Dispatcher.BeginInvoke(UpdateLabelPositions, DispatcherPriority.Loaded);
    }

    private void BuildRootGroupOrbits(IReadOnlyList<ScanResult> items, Point3D center, int visualGroupIndex, int laneGroupOffset)
    {
        if (items.Count == 0) return;
        var wirelessParents = items.Where(r => r.DeviceType is DeviceType.AccessPoint or DeviceType.WifiExtender).ToList();
        var satelliteCandidates = wirelessParents.Count == 1
            ? items.Where(r => r.DeviceType is DeviceType.Mobile or DeviceType.IoT).ToList()
            : new List<ScanResult>();
        var satellited = satelliteCandidates.ToHashSet();
        OrbitNode? wirelessParentNode = null;

        foreach (var band in new[] { OrbitBand.Infrastructure, OrbitBand.Special, OrbitBand.Peripheral, OrbitBand.Endpoint, OrbitBand.Other })
        {
            var bandItems = items
                .Where(r => BandFor(r.DeviceType) == band && !satellited.Contains(r))
                .OrderBy(r => r.IpSortKey)
                .ToList();
            if (bandItems.Count == 0) continue;

            const int nodesPerLane = 18;
            int laneCount = (int)Math.Ceiling(bandItems.Count / (double)nodesPerLane);
            for (int lane = 0; lane < laneCount; lane++)
            {
                var laneItems = bandItems.Skip(lane * nodesPerLane).Take(nodesPerLane).ToList();
                double radius = BandBaseRadius(band) + laneGroupOffset * 0.62 + lane * 1.08;
                double inclination = Degrees(GroupInclinationDegrees(visualGroupIndex) + BandInclinationDegrees(band) + lane * 4.5);
                double ascendingNode = Degrees((visualGroupIndex * 47 + (int)band * 31 + lane * 19) % 180);
                double eccentricity = Math.Clamp(0.045 + (int)band * 0.012 + lane * 0.008, 0.04, 0.16);
                double speed = BaseSpeedFor(band, radius) * (visualGroupIndex % 2 == 0 ? 1 : -1);
                AddOrbitRing(radius, inclination, ascendingNode, eccentricity, OrbitColor(band), band, center);

                for (int i = 0; i < laneItems.Count; i++)
                {
                    var r = laneItems[i];
                    double angle = -Math.PI / 2 + ((i + 0.5) / Math.Max(1.0, laneItems.Count)) * Math.PI * 2 + lane * 0.23;
                    var node = AddOrbitNode(
                        new NodeInfo(r.DeviceType, r.IpAddress, r.HostName, r.AuditGroupLabel, false, r),
                        radius, angle, inclination, ascendingNode, eccentricity,
                        NodeSizeFor(r.DeviceType, band), NodeColorFor(r.DeviceType, band),
                        speed * (1.0 + (i % 5) * 0.018), true, center);
                    if (wirelessParents.Count == 1 && ReferenceEquals(r, wirelessParents[0]))
                        wirelessParentNode = node;
                }
            }
        }

        if (wirelessParentNode is not null && satelliteCandidates.Count > 0)
        {
            const int satellitesPerLane = 8;
            int satelliteLaneCount = (int)Math.Ceiling(satelliteCandidates.Count / (double)satellitesPerLane);
            for (int lane = 0; lane < satelliteLaneCount; lane++)
            {
                double satelliteRadius = 1.05 + lane * 0.46;
                double satInclination = Degrees(24 + lane * 17 + (visualGroupIndex % 3) * 7);
                double satAscending = Degrees(35 + visualGroupIndex * 29 + lane * 41);
                AddSatelliteRing(wirelessParentNode, satelliteRadius, satInclination, satAscending);

                var laneItems = satelliteCandidates.Skip(lane * satellitesPerLane).Take(satellitesPerLane).ToList();
                for (int i = 0; i < laneItems.Count; i++)
                {
                    var r = laneItems[i];
                    double angle = ((i + 0.5) / Math.Max(1.0, laneItems.Count)) * Math.PI * 2;
                    AddSatelliteNode(
                        wirelessParentNode,
                        new NodeInfo(r.DeviceType, r.IpAddress, r.HostName, r.AuditGroupLabel, false, r),
                        satelliteRadius, angle, satInclination, satAscending,
                        r.DeviceType == DeviceType.Mobile ? 0.19 : 0.17,
                        NodeColorFor(r.DeviceType, OrbitBand.Endpoint),
                        (lane % 2 == 0 ? 1 : -1) * (0.72 + lane * 0.08 + i * 0.012));
                }
            }
        }
    }

    private TopologyRootNetwork? ResolveRootForGroup(string groupLabel, string expression)
    {
        return _topologyRoots.FirstOrDefault(r =>
            string.Equals(r.GroupLabel, groupLabel, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrWhiteSpace(expression) && string.Equals(r.Expression, expression, StringComparison.OrdinalIgnoreCase)));
    }

    private static double RootSystemSpread(int count) => count switch
    {
        <= 1 => 0,
        2 => 22,
        3 or 4 => 27,
        <= 6 => 32,
        _ => 36 + Math.Min(16, (count - 6) * 2.5)
    };

    private static Point3D RootSystemCenter(int index, int count, double spread)
    {
        if (count <= 1) return new Point3D(0, 0, 0);
        if (count == 2) return new Point3D(index == 0 ? -spread : spread, 0, 0);
        double angle = -Math.PI / 2 + Math.PI * 2 * index / Math.Max(1, count);
        return new Point3D(Math.Cos(angle) * spread, 0, Math.Sin(angle) * spread);
    }

    private NestedNetworkInfo? FindNestedRelationForGroup(IEnumerable<ScanResult> group)
    {
        var items = group.ToList();
        if (items.Count == 0 || _nestedNetworks.Count == 0) return null;
        var ips = items.Select(r => r.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var matches = _nestedNetworks
            .Where(n => !ips.Contains(n.ParentIp) && items.All(r => n.Contains(r.IpAddress)))
            .OrderByDescending(n => PrefixLength(n.Cidr))
            .ThenBy(n => n.ParentIp, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (matches.Count == 0) return null;
        int bestPrefix = PrefixLength(matches[0].Cidr);
        var best = matches.Where(n => PrefixLength(n.Cidr) == bestPrefix).ToList();
        return best.Select(n => n.ParentIp).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1 ? best[0] : null;
    }

    private bool BuildNestedSubnetSystem(IReadOnlyList<ScanResult> items, NestedNetworkInfo relation, int systemIndex)
    {
        if (!_orbitNodeByIp.TryGetValue(relation.ParentIp, out var parentNode))
            return false;

        var subnetNode = AddNestedSubnetMarker(parentNode, relation, systemIndex);
        var bands = new[] { OrbitBand.Infrastructure, OrbitBand.Special, OrbitBand.Peripheral, OrbitBand.Endpoint, OrbitBand.Other };

        foreach (var band in bands)
        {
            var bandItems = items.Where(r => BandFor(r.DeviceType) == band).OrderBy(r => r.IpSortKey).ToList();
            if (bandItems.Count == 0) continue;

            const int nodesPerLane = 8;
            int laneCount = (int)Math.Ceiling(bandItems.Count / (double)nodesPerLane);
            for (int lane = 0; lane < laneCount; lane++)
            {
                double radius = NestedBandRadius(band) + lane * 0.42;
                double inclination = Degrees(18 + (int)band * 13 + systemIndex * 5 + lane * 8);
                double ascending = Degrees(25 + systemIndex * 31 + (int)band * 27 + lane * 17);
                AddSatelliteRing(subnetNode, radius, inclination, ascending);

                var laneItems = bandItems.Skip(lane * nodesPerLane).Take(nodesPerLane).ToList();
                for (int i = 0; i < laneItems.Count; i++)
                {
                    var result = laneItems[i];
                    double angle = ((i + 0.5) / Math.Max(1.0, laneItems.Count)) * Math.PI * 2 + bandItems.Count * 0.017;
                    double size = Math.Max(0.13, NodeSizeFor(result.DeviceType, band) * 0.68);
                    double speed = (systemIndex % 2 == 0 ? 1 : -1) * (0.48 + (int)band * 0.04 + lane * 0.05 + i * 0.008);
                    AddSatelliteNode(
                        subnetNode,
                        new NodeInfo(result.DeviceType, result.IpAddress, result.HostName, result.AuditGroupLabel, false, result),
                        radius, angle, inclination, ascending, size, NodeColorFor(result.DeviceType, band), speed);
                }
            }
        }

        return true;
    }

    private OrbitNode AddNestedSubnetMarker(OrbitNode parentNode, NestedNetworkInfo relation, int systemIndex)
    {
        double radius = 1.50 + (systemIndex % 3) * 0.24;
        double inclination = Degrees(28 + (systemIndex % 5) * 13);
        double ascending = Degrees(38 + systemIndex * 37);
        AddSatelliteRing(parentNode, radius, inclination, ascending);

        Color color = relation.IsRouteConfirmed
            ? Color.FromRgb(88, 190, 155)
            : Color.FromRgb(197, 169, 70);
        double angle = Degrees((systemIndex * 97 + 23) % 360);
        var info = new NodeInfo(DeviceType.NetworkDevice, relation.Cidr, "하위 네트워크", relation.ReachabilityText, true);
        return AddSatelliteNode(parentNode, info, radius, angle, inclination, ascending, 0.25, color,
            (systemIndex % 2 == 0 ? 1 : -1) * (0.24 + (systemIndex % 4) * 0.025));
    }

    private static double NestedBandRadius(OrbitBand band) => band switch
    {
        OrbitBand.Infrastructure => 0.78,
        OrbitBand.Special => 1.08,
        OrbitBand.Peripheral => 1.36,
        OrbitBand.Endpoint => 1.66,
        _ => 1.94
    };

    private static int PrefixLength(string cidr)
    {
        var parts = cidr.Split('/');
        return parts.Length == 2 && int.TryParse(parts[1], out int prefix) ? prefix : 0;
    }

    private OrbitNode AddRootStarNode(Point3D position, NodeInfo info, double size, Color color)
    {
        var translation = CreateNodeModel(info, size, color, true);
        translation.OffsetX = position.X;
        translation.OffsetY = position.Y;
        translation.OffsetZ = position.Z;
        var label = AddLabel(position, info);
        _labels.Add(label);
        var node = new OrbitNode
        {
            Info = info,
            Translation = translation,
            Label = label,
            SemiMajorAxis = 0,
            Eccentricity = 0,
            Inclination = 0,
            AscendingNode = 0,
            CurrentAngle = 0,
            BaseAngularSpeed = 0,
            CurrentAngularSpeed = 0,
            Animated = false,
            OrbitCenter = position,
            Position = position
        };
        if (!string.IsNullOrWhiteSpace(info.Ip) && IPAddress.TryParse(info.Ip, out _))
            _orbitNodeByIp[info.Ip] = node;
        return node;
    }

    private void AddStaticNode(Point3D position, NodeInfo info, double size, Color color, bool starLike = false)
    {
        var translation = CreateNodeModel(info, size, color, starLike);
        translation.OffsetX = position.X;
        translation.OffsetY = position.Y;
        translation.OffsetZ = position.Z;
        var label = AddLabel(position, info);
        if (info.Result is not null || info.IsSynthetic)
            _labels.Add(label);
    }

    private OrbitNode AddOrbitNode(
        NodeInfo info,
        double semiMajorAxis,
        double baseAngle,
        double inclination,
        double ascendingNode,
        double eccentricity,
        double size,
        Color color,
        double angularSpeed,
        bool animated,
        Point3D? orbitCenter = null)
    {
        var center = orbitCenter ?? new Point3D();
        var translation = CreateNodeModel(info, size, color, false);
        var offset = OrbitVector(semiMajorAxis, baseAngle, inclination, ascendingNode, eccentricity);
        var position = center + offset;
        translation.OffsetX = position.X;
        translation.OffsetY = position.Y;
        translation.OffsetZ = position.Z;
        var label = AddLabel(position, info);
        _labels.Add(label);
        var node = new OrbitNode
        {
            Info = info,
            Translation = translation,
            Label = label,
            SemiMajorAxis = semiMajorAxis,
            Eccentricity = eccentricity,
            Inclination = inclination,
            AscendingNode = ascendingNode,
            CurrentAngle = baseAngle,
            BaseAngularSpeed = angularSpeed,
            CurrentAngularSpeed = 0,
            Animated = animated,
            OrbitCenter = center,
            Position = position
        };
        _orbitNodes.Add(node);
        if (!info.IsSynthetic && !string.IsNullOrWhiteSpace(info.Ip))
            _orbitNodeByIp[info.Ip] = node;
        return node;
    }

    private OrbitNode AddSatelliteNode(
        OrbitNode parent,
        NodeInfo info,
        double satelliteRadius,
        double baseAngle,
        double inclination,
        double ascendingNode,
        double size,
        Color color,
        double angularSpeed)
    {
        var translation = CreateNodeModel(info, size, color, false);
        var local = OrbitVector(satelliteRadius, baseAngle, inclination, ascendingNode, 0.06);
        var position = parent.Position + local;
        translation.OffsetX = position.X;
        translation.OffsetY = position.Y;
        translation.OffsetZ = position.Z;
        var label = AddLabel(position, info);
        _labels.Add(label);
        var node = new OrbitNode
        {
            Info = info,
            Translation = translation,
            Label = label,
            SemiMajorAxis = satelliteRadius,
            SatelliteRadius = satelliteRadius,
            Eccentricity = 0.06,
            Inclination = inclination,
            AscendingNode = ascendingNode,
            CurrentAngle = baseAngle,
            BaseAngularSpeed = angularSpeed,
            CurrentAngularSpeed = 0,
            Animated = true,
            IsSatellite = true,
            Parent = parent,
            OrbitCenter = parent.Position,
            Position = position
        };
        _orbitNodes.Add(node);
        if (!info.IsSynthetic && !string.IsNullOrWhiteSpace(info.Ip))
            _orbitNodeByIp[info.Ip] = node;
        return node;
    }

    private TranslateTransform3D CreateNodeModel(NodeInfo info, double size, Color color, bool starLike)
    {
        // Planet-style topology: every real device is rendered as a sphere.
        var mesh = CreateSphereMesh(new Point3D(0, 0, 0), size, 20, 14);
        var material = new MaterialGroup();
        material.Children.Add(new DiffuseMaterial(new SolidColorBrush(color)));
        material.Children.Add(new SpecularMaterial(new SolidColorBrush(Color.FromRgb(245, 245, 245)), starLike ? 72 : 38));
        if (starLike)
            material.Children.Add(new EmissiveMaterial(new SolidColorBrush(Color.FromArgb(82, 250, 216, 59))));

        if (!info.IsSynthetic && !string.IsNullOrWhiteSpace(info.Ip))
        {
            var auditGlow = new SolidColorBrush(Color.FromArgb(0, 250, 176, 59));
            material.Children.Add(new EmissiveMaterial(auditGlow));
            _auditGlowByIp[info.Ip] = auditGlow;

            var trafficGlow = new SolidColorBrush(Color.FromArgb(0, 98, 217, 166));
            material.Children.Add(new EmissiveMaterial(trafficGlow));
            _trafficGlowByIp[info.Ip] = trafficGlow;

            // Security risk is a separate emissive layer so LIVE/audit state remains visible.
            var securityGlow = new SolidColorBrush(Color.FromArgb(0, 244, 67, 54));
            material.Children.Add(new EmissiveMaterial(securityGlow));
            _securityGlowByIp[info.Ip] = securityGlow;
        }

        var translation = new TranslateTransform3D();
        var model = new GeometryModel3D(mesh, material)
        {
            BackMaterial = material,
            Transform = translation
        };
        _modelInfo[model] = info;
        _nodeVisuals.Add((model, info));
        TopologyViewport.Children.Add(new ModelVisual3D { Content = model });
        return translation;
    }

    private LabelVisual AddLabel(Point3D position, NodeInfo info)
    {
        bool important = info.IsSynthetic || IsStrongInfrastructure(info.Type) || IsSpecialAsset(info.Type) ||
                         info.Type is DeviceType.Printer or DeviceType.Camera or DeviceType.Ups or DeviceType.Internet;
        var borderColor = LabelAccent(info.Type, info.IsSynthetic);

        var title = new TextBlock
        {
            Text = BuildLabelTitle(info),
            Foreground = new SolidColorBrush(Color.FromRgb(238, 238, 238)),
            FontSize = important ? 10.8 : 9.6,
            FontWeight = important ? FontWeights.SemiBold : FontWeights.Normal,
            TextTrimming = TextTrimming.CharacterEllipsis,
            MaxWidth = important ? 230 : 190
        };

        var stack = new StackPanel();
        stack.Children.Add(title);
        string secondary = BuildLabelSecondary(info);
        if (!string.IsNullOrWhiteSpace(secondary))
        {
            stack.Children.Add(new TextBlock
            {
                Text = secondary,
                Foreground = new SolidColorBrush(Color.FromRgb(145, 145, 145)),
                FontSize = important ? 9.3 : 8.7,
                Margin = new Thickness(0, 1, 0, 0),
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = important ? 230 : 190
            });
        }

        TextBlock? activityText = null;
        if (info.Result is not null)
        {
            activityText = new TextBlock
            {
                Text = "",
                Foreground = new SolidColorBrush(Color.FromRgb(98, 217, 166)),
                FontSize = important ? 9.1 : 8.5,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 2, 0, 0),
                Visibility = Visibility.Collapsed
            };
            stack.Children.Add(activityText);
        }

        bool labelInteractive = !info.IsSynthetic && !string.IsNullOrWhiteSpace(info.Ip);
        var border = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(220, 15, 15, 15)),
            BorderBrush = new SolidColorBrush(borderColor),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(6, 3, 6, 3),
            Child = stack,
            SnapsToDevicePixels = true,
            Tag = info,
            Cursor = labelInteractive ? Cursors.Hand : Cursors.Arrow,
            ToolTip = info.Result is not null ? "클릭하여 장비 상세 보기" : labelInteractive ? "클릭하여 관찰 노드 정보 보기" : null
        };
        if (labelInteractive)
        {
            border.MouseLeftButtonUp += Label_MouseLeftButtonUp;
            border.MouseEnter += Label_MouseEnter;
            border.MouseLeave += Label_MouseLeave;
            border.PreviewMouseWheel += Label_MouseWheel;
        }
        LabelCanvas.Children.Add(border);

        return new LabelVisual
        {
            Position = position,
            Info = info,
            Element = border,
            ActivityText = activityText,
            Important = important
        };
    }

    private void Label_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (sender is not Border border || border.Tag is not NodeInfo info)
            return;

        _selectedInfo = info;
        ShowNodeInfo(info);
        UpdateLabelPositions();
        e.Handled = true;

        if (info.Result is ScanResult result)
        {
            // Open after the current mouse input cycle has completed. This avoids nested WPF input/layout work.
            Dispatcher.BeginInvoke(new Action(() => OpenDeviceDetail(result)), DispatcherPriority.Input);
        }
    }

    private void Label_MouseEnter(object sender, MouseEventArgs e)
    {
        if (sender is not Border border || border.Tag is not NodeInfo info || info.IsSynthetic)
            return;

        border.Background = new SolidColorBrush(Color.FromArgb(242, 31, 31, 31));
        border.BorderBrush = new SolidColorBrush(Color.FromRgb(250, 216, 59));
        border.BorderThickness = new Thickness(1.35);
        border.Opacity = 1.0;
    }

    private void Label_MouseLeave(object sender, MouseEventArgs e)
    {
        // Restore the normal depth/filter/selection-driven label appearance.
        UpdateLabelPositions();
    }

    private void Label_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        // Keep wheel zoom working even when the pointer is directly over a label card.
        Viewport_MouseWheel(ViewportInputSurface, e);
    }

    private void AddOrbitRing(double semiMajorAxis, double inclination, double ascendingNode, double eccentricity, Color color, OrbitBand band, Point3D? orbitCenter = null)
    {
        var mesh = CreateOrbitRingMesh(semiMajorAxis, inclination, ascendingNode, eccentricity, 0.018, 192);
        var brush = new SolidColorBrush(color) { Opacity = 0.64 };
        var material = new DiffuseMaterial(brush);
        var center = orbitCenter ?? new Point3D();
        var model = new GeometryModel3D(mesh, material)
        {
            BackMaterial = material,
            Transform = new TranslateTransform3D(center.X, center.Y, center.Z)
        };
        _orbitRingVisuals.Add((model, band, brush));
        TopologyViewport.Children.Add(new ModelVisual3D { Content = model });
    }

    private void AddSatelliteRing(OrbitNode parent, double radius, double inclination, double ascendingNode)
    {
        var mesh = CreateOrbitRingMesh(radius, inclination, ascendingNode, 0.02, 0.010, 72);
        var brush = new SolidColorBrush(Color.FromArgb(105, 106, 148, 168)) { Opacity = 0.62 };
        var material = new DiffuseMaterial(brush);
        var translation = new TranslateTransform3D(parent.Position.X, parent.Position.Y, parent.Position.Z);
        var model = new GeometryModel3D(mesh, material)
        {
            BackMaterial = material,
            Transform = translation
        };
        TopologyViewport.Children.Add(new ModelVisual3D { Content = model });
        _satelliteRings.Add(new SatelliteRingVisual { Parent = parent, Translation = translation, Brush = brush });
    }

    private void OrbitTimer_Tick(object? sender, EventArgs e)
    {
        var now = DateTime.UtcNow;
        double dt = Math.Clamp((now - _lastOrbitTick).TotalSeconds, 0, 0.12);
        _lastOrbitTick = now;
        UpdateOrbitMotion(dt);
    }

    private void UpdateOrbitMotion(double dt)
    {
        double targetFactor = _orbitMotionEnabled ? _speedPreset : 0.0;
        double response = targetFactor > _motionSpeedFactor
            ? 1.6 + Math.Min(10.0, targetFactor) * 0.58
            : 2.8 + Math.Min(10.0, _motionSpeedFactor) * 0.22;
        _motionSpeedFactor = MoveTowards(_motionSpeedFactor, targetFactor, response * dt);

        foreach (var node in _orbitNodes.Where(n => !n.IsSatellite))
            UpdateNodeOrbit(node, dt, null);

        // Satellites are stored parent-first. Updating them before their rings means second/third
        // level router systems follow their moving parent in the same frame rather than one frame late.
        foreach (var node in _orbitNodes.Where(n => n.IsSatellite))
            UpdateNodeOrbit(node, dt, node.Parent?.Position);

        foreach (var ring in _satelliteRings)
        {
            var p = ring.Parent.Position;
            ring.Translation.OffsetX = p.X;
            ring.Translation.OffsetY = p.Y;
            ring.Translation.OffsetZ = p.Z;
        }

        if (MotionStateText is not null)
            MotionStateText.Text = $"가속도 적용 · 속도 {_motionSpeedFactor:0.00}× / 목표 {targetFactor:0.0}×";

        UpdateGatewayHalo();
        UpdateTrafficVisuals();
        bool cameraChanged = UpdateCameraDynamics(dt);
        if (cameraChanged) UpdateCamera(); else UpdateLabelPositions();
    }

    private void UpdateNodeOrbit(OrbitNode node, double dt, Point3D? parentPosition)
    {
        if (node.Animated)
        {
            // Slightly eccentric orbit: angular target is faster near periapsis and slower near apoapsis.
            double orbitalModulation = 1.0 + node.Eccentricity * 1.85 * Math.Cos(node.CurrentAngle);
            double targetAngularSpeed = node.BaseAngularSpeed * _motionSpeedFactor * orbitalModulation;
            double speedBoost = 1.0 + Math.Min(10.0, _motionSpeedFactor) * 0.18;
            double angularAcceleration = Math.Max(0.12, Math.Abs(node.BaseAngularSpeed) * (node.IsSatellite ? 6.8 : 4.4) * speedBoost);
            node.CurrentAngularSpeed = MoveTowards(node.CurrentAngularSpeed, targetAngularSpeed, angularAcceleration * dt);
            node.CurrentAngle = NormalizeAngle(node.CurrentAngle + node.CurrentAngularSpeed * dt);
        }

        var offset = OrbitVector(node.SemiMajorAxis, node.CurrentAngle, node.Inclination, node.AscendingNode, node.Eccentricity);
        var position = parentPosition.HasValue ? parentPosition.Value + offset : node.OrbitCenter + offset;
        node.Position = position;
        node.Translation.OffsetX = position.X;
        node.Translation.OffsetY = position.Y;
        node.Translation.OffsetZ = position.Z;
        node.Label.Position = position;
    }

    private void UpdateTrafficVisuals()
    {
        if (_trafficProvider is not null)
            _trafficSnapshot = _trafficProvider();
        if (_trafficAuditProvider is not null)
            _trafficAuditSnapshot = _trafficAuditProvider();
        if (_securityRelationshipProvider is not null)
            _securityRelationshipSnapshot = _securityRelationshipProvider();
        if (_externalObservationProvider is not null)
            _externalObservationSnapshot = _externalObservationProvider();
        if (_captureCoverageProvider is not null)
            _captureCoverageSnapshot = _captureCoverageProvider();
        RebuildTopologySignificance();
        if (_externalObservationProvider is not null || _captureCoverageProvider is not null || _securityRelationshipProvider is not null)
        {
            UpdateExternalHistoryUi();
            UpdateCaptureCoverageUi();
            QueueExternalSceneRefreshIfNeeded();
        }

        foreach (var pair in _auditGlowByIp)
        {
            if (_trafficAuditSnapshot.Nodes.FirstOrDefault(n => string.Equals(n.IpAddress, pair.Key, StringComparison.OrdinalIgnoreCase)) is { } auditNode && auditNode.TotalPackets > 0)
            {
                double strength = Math.Clamp(Math.Log10(1.0 + auditNode.TotalBytes) / 8.0, 0.10, 0.62);
                byte alpha = (byte)Math.Clamp(20 + strength * 150, 20, 118);
                pair.Value.Color = Color.FromArgb(alpha, 250, 176, 59);
            }
            else
            {
                pair.Value.Color = Color.FromArgb(0, 250, 176, 59);
            }
        }

        foreach (var pair in _trafficGlowByIp)
        {
            if (_trafficSnapshot.Nodes.TryGetValue(pair.Key, out var stat) && stat.IsActive)
            {
                double activity = Math.Max(stat.TotalBytesPerSecond, stat.TotalPacketsPerSecond * 96.0);
                double strength = Math.Clamp(Math.Log10(1.0 + activity) / 5.0, 0.18, 1.0);
                byte alpha = (byte)Math.Clamp(38 + strength * 180, 38, 218);
                pair.Value.Color = Color.FromArgb(alpha, 98, 217, 166);
            }
            else
            {
                pair.Value.Color = Color.FromArgb(0, 98, 217, 166);
            }
        }

        var securityNodes = _securityRelationshipSnapshot.Nodes
            .ToDictionary(n => n.IpAddress, StringComparer.OrdinalIgnoreCase);
        foreach (var pair in _securityGlowByIp)
        {
            if (securityNodes.TryGetValue(pair.Key, out var security) && security.RiskScore >= 25)
            {
                Color riskColor = GetSecurityColor(security.RiskLevel);
                byte alpha = (byte)Math.Clamp(42 + security.RiskScore * 1.75, 42, 217);
                pair.Value.Color = Color.FromArgb(alpha, riskColor.R, riskColor.G, riskColor.B);
            }
            else
            {
                pair.Value.Color = Color.FromArgb(0, 244, 67, 54);
            }
        }

        var auditNodes = _trafficAuditSnapshot.Nodes.ToDictionary(n => n.IpAddress, StringComparer.OrdinalIgnoreCase);
        foreach (var label in _labels)
        {
            if (label.ActivityText is null || label.Info.IsSynthetic || string.IsNullOrWhiteSpace(label.Info.Ip)) continue;
            securityNodes.TryGetValue(label.Info.Ip, out var security);

            if (_trafficSnapshot.Nodes.TryGetValue(label.Info.Ip, out var stat) && stat.IsActive)
            {
                string protocol = string.IsNullOrWhiteSpace(stat.LastProtocol) ? "IP" : stat.LastProtocol;
                string port = stat.LastPort.HasValue ? $"/{stat.LastPort.Value}" : string.Empty;
                if (security is { RiskScore: >= 25 })
                {
                    label.ActivityText.Text = $"{security.RiskLevel} {security.RiskScore} · ↕ {stat.RateText} · {protocol}{port}";
                    label.ActivityText.Foreground = new SolidColorBrush(GetSecurityColor(security.RiskLevel));
                }
                else
                {
                    label.ActivityText.Text = $"↕ {stat.RateText} · {stat.TotalPacketsPerSecond:0.#} pkt/s · {protocol}{port}";
                    label.ActivityText.Foreground = new SolidColorBrush(Color.FromRgb(98, 217, 166));
                }
                label.ActivityText.Visibility = Visibility.Visible;
            }
            else if (security is { RiskScore: >= 25 })
            {
                string reason = security.Reasons.Count > 0 ? string.Join(" / ", security.Reasons.Take(2)) : "행동 이상 징후";
                label.ActivityText.Text = $"RISK {security.RiskScore} · {reason}";
                label.ActivityText.Foreground = new SolidColorBrush(GetSecurityColor(security.RiskLevel));
                label.ActivityText.Visibility = Visibility.Visible;
            }
            else if (auditNodes.TryGetValue(label.Info.Ip, out var auditNode) && auditNode.TotalPackets > 0)
            {
                string prefix = _trafficAuditSnapshot.IsRecording ? "REC" : "AUDIT";
                label.ActivityText.Text = $"{prefix} · {auditNode.TotalBytesText} · {auditNode.TotalPackets:N0} pkt";
                label.ActivityText.Foreground = new SolidColorBrush(Color.FromRgb(235, 184, 78));
                label.ActivityText.Visibility = Visibility.Visible;
            }
            else if (_externalObservationSnapshot.Nodes.FirstOrDefault(n => string.Equals(n.IpAddress, label.Info.Ip, StringComparison.OrdinalIgnoreCase)) is { } observed && observed.Packets > 0)
            {
                label.ActivityText.Text = $"OBS · {observed.BytesText} · {observed.Packets:N0} pkt · {observed.LastSeenText}";
                label.ActivityText.Foreground = new SolidColorBrush(Color.FromRgb(190, 173, 227));
                label.ActivityText.Visibility = Visibility.Visible;
            }
            else
            {
                label.ActivityText.Text = string.Empty;
                label.ActivityText.Visibility = Visibility.Collapsed;
            }
        }

        if (TrafficLiveText is not null)
        {
            TrafficLiveText.Text = _trafficSnapshot.TotalCapturedPackets > 0
                ? $"LIVE · {_trafficSnapshot.CurrentRateText} · {_trafficSnapshot.CurrentPacketsPerSecond:0.#} pkt/s"
                : "캡처 대기";
            TrafficLiveText.Foreground = new SolidColorBrush(_trafficSnapshot.TotalCapturedPackets > 0
                ? Color.FromRgb(98, 217, 166)
                : Color.FromRgb(125, 125, 125));
        }

        if (TrafficAuditText is not null)
        {
            if (string.IsNullOrWhiteSpace(_trafficAuditSnapshot.SessionId))
            {
                TrafficAuditText.Text = "기록 없음";
                TrafficAuditText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
            else
            {
                string state = _trafficAuditSnapshot.IsRecording ? "REC" : "LAST";
                TrafficAuditText.Text = $"{state} · {_trafficAuditSnapshot.DurationText} · {_trafficAuditSnapshot.TotalPackets:N0} pkt · {_trafficAuditSnapshot.UniqueFlowCount:N0} flows";
                TrafficAuditText.Foreground = new SolidColorBrush(_trafficAuditSnapshot.IsRecording
                    ? Color.FromRgb(250, 216, 59)
                    : Color.FromRgb(222, 179, 82));
            }
        }
        if (TrafficAuditToggleButton is not null)
        {
            TrafficAuditToggleButton.Content = _trafficAuditSnapshot.IsRecording ? "■ 기록 종료" : "● 기록 시작";
            TrafficAuditToggleButton.IsEnabled = _trafficAuditToggle is not null;
        }
        if (TrafficAuditOpenButton is not null)
        {
            TrafficAuditOpenButton.IsEnabled = _trafficAuditOpen is not null && (_trafficAuditSnapshot.HasData || _trafficAuditSnapshot.IsRecording);
        }

        UpdateSecurityRelationshipUi();
        if (_selectedInfo is not null)
            UpdateSelectedTrafficInfo(_selectedInfo);
    }

    private static Color GetSecurityColor(string? level) => (level ?? string.Empty).ToUpperInvariant() switch
    {
        "HIGH" => Color.FromRgb(244, 67, 54),
        "MEDIUM" => Color.FromRgb(255, 145, 48),
        "WATCH" => Color.FromRgb(250, 216, 59),
        _ => Color.FromRgb(125, 125, 125)
    };

    private void UpdateSecurityRelationshipUi()
    {
        if (SecurityRelationshipText is not null)
        {
            if (!_securityRelationshipSnapshot.HasData)
            {
                SecurityRelationshipText.Text = "분석 대기";
                SecurityRelationshipText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
            else
            {
                SecurityRelationshipText.Text =
                    $"의심 {_securityRelationshipSnapshot.SuspiciousNodeCount:N0} · H {_securityRelationshipSnapshot.HighCount:N0} · M {_securityRelationshipSnapshot.MediumCount:N0} · W {_securityRelationshipSnapshot.WatchCount:N0} · " +
                    $"DNS {_securityRelationshipSnapshot.DnsAnomalyNodeCount:N0} · BL {_securityRelationshipSnapshot.BaselineReadyCount:N0}/{_securityRelationshipSnapshot.Nodes.Count:N0} (이탈 {_securityRelationshipSnapshot.BaselineAnomalyCount:N0}) · " +
                    $"비콘 {_securityRelationshipSnapshot.BeaconNodeCount:N0} · 횡적 {_securityRelationshipSnapshot.LateralMovementNodeCount:N0} · 관계 {_securityRelationshipSnapshot.SuspiciousFlows.Count:N0}";
                SecurityRelationshipText.Foreground = new SolidColorBrush(_securityRelationshipSnapshot.HighCount > 0
                    ? Color.FromRgb(244, 99, 85)
                    : _securityRelationshipSnapshot.MediumCount > 0
                        ? Color.FromRgb(255, 164, 73)
                        : _securityRelationshipSnapshot.WatchCount > 0
                            ? Color.FromRgb(250, 216, 59)
                            : Color.FromRgb(142, 142, 142));
            }
        }

        if (SecurityRelationshipResetButton is not null)
            SecurityRelationshipResetButton.IsEnabled = _securityRelationshipClear is not null && _securityRelationshipSnapshot.HasData;
    }

    private void SecurityRelationshipReset_Click(object sender, RoutedEventArgs e)
    {
        if (_securityRelationshipClear is null || !_securityRelationshipSnapshot.HasData) return;
        var answer = ThemedMessageBox.Show(
            "현재 실행 중 누적한 관계도 보안 분석 이력을 초기화하시겠습니까?\n\n패킷 캡처가 계속 중이면 이후 관찰되는 통신부터 다시 분석됩니다.",
            "NetLoom · 관계도 보안 감사", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        _securityRelationshipClear();
        _securityRelationshipSnapshot = _securityRelationshipProvider?.Invoke() ?? SecurityRelationshipSnapshot.Empty;
        UpdateTrafficVisuals();
        UpdateLabelPositions();
    }

    private void SecurityBaselineReset_Click(object sender, RoutedEventArgs e)
    {
        if (_securityBaselineClear is null) return;
        var answer = ThemedMessageBox.Show(
            "장비별 정상 행동 Baseline 학습값을 전체 삭제하시겠습니까?\n\n현재 관계도 보안 분석 세션과 External 이력은 유지됩니다.",
            "NetLoom · Baseline 초기화", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        _securityBaselineClear();
        _securityRelationshipSnapshot = _securityRelationshipProvider?.Invoke() ?? SecurityRelationshipSnapshot.Empty;
        UpdateTrafficVisuals();
        UpdateLabelPositions();
    }

    private async void TrafficAuditToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_trafficAuditToggle is null) return;
        TrafficAuditToggleButton.IsEnabled = false;
        try
        {
            await _trafficAuditToggle();
            _trafficAuditSnapshot = _trafficAuditProvider?.Invoke() ?? _trafficAuditSnapshot;
            UpdateTrafficVisuals();
            UpdateLabelPositions();
        }
        finally
        {
            TrafficAuditToggleButton.IsEnabled = true;
        }
    }

    private void TrafficAuditOpen_Click(object sender, RoutedEventArgs e)
    {
        _trafficAuditOpen?.Invoke();
    }

    private void PacketInspector_Click(object sender, RoutedEventArgs e)
    {
        string? nodeFilter = _selectedInfo is { IsSynthetic: false } &&
                             !string.IsNullOrWhiteSpace(_selectedInfo.Ip)
            ? _selectedInfo.Ip
            : null;
        _packetInspectorOpen?.Invoke(nodeFilter);
    }

    private static double MoveTowards(double current, double target, double maxDelta)
    {
        if (Math.Abs(target - current) <= maxDelta) return target;
        return current + Math.Sign(target - current) * maxDelta;
    }

    private static double NormalizeAngle(double angle)
    {
        double twoPi = Math.PI * 2;
        angle %= twoPi;
        if (angle < 0) angle += twoPi;
        return angle;
    }

    private static Point3D OrbitPosition(double semiMajorAxis, double angle, double inclination, double ascendingNode, double eccentricity)
    {
        var v = OrbitVector(semiMajorAxis, angle, inclination, ascendingNode, eccentricity);
        return new Point3D(v.X, v.Y, v.Z);
    }

    private static Vector3D OrbitVector(double semiMajorAxis, double angle, double inclination, double ascendingNode, double eccentricity)
    {
        double e = Math.Clamp(eccentricity, 0, 0.35);
        double a = Math.Max(0.08, semiMajorAxis);
        double b = a * Math.Sqrt(1 - e * e);

        // Gateway remains near one focus of the ellipse.
        double x = a * (Math.Cos(angle) - e);
        double z = b * Math.Sin(angle);

        // Rotate the orbital plane around X (inclination), then Y (ascending node).
        double ci = Math.Cos(inclination);
        double si = Math.Sin(inclination);
        double y1 = -z * si;
        double z1 = z * ci;

        double co = Math.Cos(ascendingNode);
        double so = Math.Sin(ascendingNode);
        double x2 = x * co + z1 * so;
        double z2 = -x * so + z1 * co;
        return new Vector3D(x2, y1, z2);
    }

    private void Viewport_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        TopologyViewport.Focus();
        _lastMouseInput = DateTime.UtcNow;
        var p = e.GetPosition(ViewportInputSurface);
        bool hasHit = TryHitNode(p, out var hitInfo, out var hitPoint);

        if (e.ClickCount >= 2)
        {
            _dragging = false;
            _panning = false;
            _pressedInfo = null;
            _pendingOrbitPivot = null;
            _orbitPivotApplied = false;
            _panVelocity = new Vector3D();

            if (hasHit && hitInfo is not null && !IsInfoHidden(hitInfo))
            {
                _selectedInfo = hitInfo;
                ShowNodeInfo(hitInfo);
                var focusPoint = GetNodeWorldPosition(hitInfo, hitPoint);
                RetargetCameraPreservePosition(focusPoint);
                _targetDistance = Math.Clamp(_distance * 0.68, 5.5, 70.0);
                StatusText.Text = $"카메라 포커스 · {BuildLabelTitle(hitInfo)}";
                UpdateLabelPositions();
            }
            else
            {
                // Empty-space double click used to reset the camera. During quick orbit gestures
                // this could be triggered unintentionally and looked like a random view reset.
                // Camera reset is now explicit through the "시점 초기화" button only.
                StatusText.Text = "빈 공간 더블클릭 · 현재 시점 유지";
                UpdateLabelPositions();
            }

            e.Handled = true;
            return;
        }

        bool shiftPan = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift;
        _pressedInfo = null;
        _pendingOrbitPivot = null;
        _orbitPivotApplied = false;

        if (!shiftPan && hasHit && hitInfo is not null && !IsInfoHidden(hitInfo))
        {
            _selectedInfo = hitInfo;
            _pressedInfo = hitInfo;
            _pendingOrbitPivot = GetNodeWorldPosition(hitInfo, hitPoint);
            ShowNodeInfo(hitInfo);
            UpdateLabelPositions();
        }

        _lastMouse = p;
        _lastMouseInput = DateTime.UtcNow;
        _dragDistance = 0;
        _dragging = !shiftPan;
        _panning = shiftPan;
        _yawVelocity = 0;
        _pitchVelocity = 0;
        _panVelocity = new Vector3D();
        Mouse.Capture(ViewportInputSurface, CaptureMode.Element);
        e.Handled = true;
    }

    private void Viewport_MouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        TopologyViewport.Focus();
        _lastMouseInput = DateTime.UtcNow;
        _lastMouse = e.GetPosition(ViewportInputSurface);
        _panning = true;
        _dragging = false;
        _pressedInfo = null;
        _pendingOrbitPivot = null;
        _orbitPivotApplied = false;
        _yawVelocity = 0;
        _pitchVelocity = 0;
        _panVelocity = new Vector3D();
        Mouse.Capture(ViewportInputSurface, CaptureMode.Element);
        e.Handled = true;
    }

    private void Viewport_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_dragging && !_panning) return;

        var p = e.GetPosition(ViewportInputSurface);
        var delta = p - _lastMouse;
        if (Math.Abs(delta.X) < 0.01 && Math.Abs(delta.Y) < 0.01) return;

        var now = DateTime.UtcNow;
        double inputDt = Math.Clamp((now - _lastMouseInput).TotalSeconds, 0.008, 0.08);
        _lastMouse = p;
        _lastMouseInput = now;
        _dragDistance += Math.Abs(delta.X) + Math.Abs(delta.Y);

        bool shiftPan = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift;
        if (_dragging && e.LeftButton == MouseButtonState.Pressed && !shiftPan)
        {
            // If a drag begins on a node, promote that node to the orbit pivot only after
            // the gesture is clearly a drag. A simple click therefore still opens details.
            if (!_orbitPivotApplied && _dragDistance > 7 && _pendingOrbitPivot.HasValue)
            {
                RetargetCameraPreservePosition(_pendingOrbitPivot.Value);
                _orbitPivotApplied = true;
            }

            // Game-like orbit camera: horizontal movement yaws, vertical movement pitches.
            // Sensitivity scales slightly with viewport size so edge areas feel the same as the center.
            double basis = Math.Max(420.0, Math.Min(ViewportInputSurface.ActualWidth, ViewportInputSurface.ActualHeight));
            double sensitivity = Math.Clamp(520.0 / basis, 0.34, 0.62);
            double yawDelta = delta.X * sensitivity;
            double pitchDelta = -delta.Y * sensitivity * 0.84;
            _yaw += yawDelta;
            _pitch = Math.Clamp(_pitch + pitchDelta, -86, 86);
            _yawVelocity = yawDelta / inputDt;
            _pitchVelocity = pitchDelta / inputDt;
            UpdateCamera();
            e.Handled = true;
            return;
        }

        if ((_panning && (e.RightButton == MouseButtonState.Pressed || e.LeftButton == MouseButtonState.Pressed)) ||
            (_dragging && e.LeftButton == MouseButtonState.Pressed && shiftPan))
        {
            _panning = true;
            _dragging = false;
            _pendingOrbitPivot = null;
            PanCamera(delta, inputDt);
            UpdateCamera();
            e.Handled = true;
        }
    }

    private void Viewport_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        bool wasDragging = _dragging;
        _dragging = false;
        if (_panning && e.RightButton != MouseButtonState.Pressed)
            _panning = false;
        if (!_panning && Mouse.Captured == ViewportInputSurface) Mouse.Capture(null);

        var clicked = _pressedInfo;
        _pressedInfo = null;
        _pendingOrbitPivot = null;
        _orbitPivotApplied = false;
        if (wasDragging && _dragDistance <= 7 && clicked?.Result is ScanResult result)
            OpenDeviceDetail(result);
        e.Handled = true;
    }

    private void Viewport_MouseRightButtonUp(object sender, MouseButtonEventArgs e)
    {
        _panning = false;
        if (!_dragging && Mouse.Captured == ViewportInputSurface) Mouse.Capture(null);
        e.Handled = true;
    }

    private void Viewport_LostMouseCapture(object sender, MouseEventArgs e)
    {
        _dragging = false;
        _panning = false;
        _pressedInfo = null;
        _pendingOrbitPivot = null;
        _orbitPivotApplied = false;
    }

    private void Viewport_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        _lastMouseInput = DateTime.UtcNow;
        var pointer = e.GetPosition(ViewportInputSurface);
        bool zoomIn = e.Delta > 0;
        double currentTarget = _targetDistance <= 0 ? _distance : _targetDistance;
        double steps = Math.Max(1.0, Math.Abs(e.Delta) / 120.0);
        double factor = Math.Pow(zoomIn ? 0.84 : 1.19, steps);
        _targetDistance = Math.Clamp(currentTarget * factor, 3.5, 180.0);

        // Zoom-to-cursor across the entire viewport, not only when the cursor is over a 3D mesh.
        // If a node is under the pointer use the actual 3D hit point; otherwise project the cursor
        // onto the current target plane. This makes zooming at the edges feel as responsive as center zoom.
        Point3D aim = TryHitNode(pointer, out _, out var hitPoint)
            ? hitPoint
            : GetPointerPointOnTargetPlane(pointer);
        Vector3D towardAim = aim - _target;
        double targetShift = zoomIn ? 0.16 : 0.05;
        _target += towardAim * targetShift;

        e.Handled = true;
    }

    private bool TryHitNode(Point point, out NodeInfo? info, out Point3D hitPoint)
    {
        info = null;
        hitPoint = new Point3D();
        if (TopologyViewport.ActualWidth <= 1 || TopologyViewport.ActualHeight <= 1)
            return false;

        if (VisualTreeHelper.HitTest(TopologyViewport, point) is not RayMeshGeometry3DHitTestResult hit || hit.ModelHit is null)
            return false;

        hitPoint = hit.PointHit;
        if (!_modelInfo.TryGetValue(hit.ModelHit, out var resolved) || IsInfoHidden(resolved))
            return false;

        info = resolved;
        return true;
    }

    private Point3D GetNodeWorldPosition(NodeInfo info, Point3D fallback)
    {
        var moving = _orbitNodes.FirstOrDefault(n => ReferenceEquals(n.Info, info) ||
            (!string.IsNullOrWhiteSpace(info.Ip) && string.Equals(n.Info.Ip, info.Ip, StringComparison.OrdinalIgnoreCase)));
        if (moving is not null) return moving.Position;

        var label = _labels.FirstOrDefault(l => ReferenceEquals(l.Info, info) ||
            (!string.IsNullOrWhiteSpace(info.Ip) && string.Equals(l.Info.Ip, info.Ip, StringComparison.OrdinalIgnoreCase)));
        return label?.Position ?? fallback;
    }

    private void RetargetCameraPreservePosition(Point3D newTarget)
    {
        Point3D currentPosition = _camera.Position;
        Vector3D offset = currentPosition - newTarget;
        double distance = offset.Length;
        if (distance < 0.05)
            return;

        _target = newTarget;
        _distance = Math.Clamp(distance, 3.5, 180.0);
        _targetDistance = _distance;
        _pitch = Math.Asin(Math.Clamp(offset.Y / distance, -1.0, 1.0)) * 180.0 / Math.PI;
        _yaw = Math.Atan2(offset.Z, offset.X) * 180.0 / Math.PI;
        _yawVelocity = 0;
        _pitchVelocity = 0;
        _panVelocity = new Vector3D();
        UpdateCamera();
    }

    private Point3D GetPointerPointOnTargetPlane(Point pointer)
    {
        double width = Math.Max(1.0, ViewportInputSurface.ActualWidth);
        double height = Math.Max(1.0, ViewportInputSurface.ActualHeight);

        Vector3D forward = _camera.LookDirection;
        if (forward.Length < 0.0001) forward = new Vector3D(0, 0, -1);
        forward.Normalize();
        Vector3D up = _camera.UpDirection;
        if (up.Length < 0.0001) up = new Vector3D(0, 1, 0);
        up.Normalize();
        Vector3D right = Vector3D.CrossProduct(forward, up);
        if (right.Length < 0.0001) right = new Vector3D(1, 0, 0);
        right.Normalize();
        Vector3D trueUp = Vector3D.CrossProduct(right, forward);
        trueUp.Normalize();

        double halfHeight = Math.Max(3.5, _distance) * Math.Tan(_camera.FieldOfView * Math.PI / 360.0);
        double halfWidth = halfHeight * width / height;
        double nx = (pointer.X / width - 0.5) * 2.0;
        double ny = (0.5 - pointer.Y / height) * 2.0;
        return _target + right * (nx * halfWidth) + trueUp * (ny * halfHeight);
    }

    private void PanCamera(Vector delta, double inputDt)
    {
        Vector3D forward = _camera.LookDirection;
        if (forward.Length < 0.0001) return;
        forward.Normalize();
        Vector3D up = _camera.UpDirection;
        if (up.Length < 0.0001) up = new Vector3D(0, 1, 0);
        up.Normalize();
        Vector3D right = Vector3D.CrossProduct(forward, up);
        if (right.Length < 0.0001) return;
        right.Normalize();
        Vector3D trueUp = Vector3D.CrossProduct(right, forward);
        trueUp.Normalize();

        double height = Math.Max(200, ViewportInputSurface.ActualHeight);
        double worldPerPixel = 2.0 * Math.Max(3.5, _distance) * Math.Tan(_camera.FieldOfView * Math.PI / 360.0) / height;
        Vector3D shift = right * (-delta.X * worldPerPixel) + trueUp * (delta.Y * worldPerPixel);
        _target += shift;
        _panVelocity = shift * (1.0 / Math.Max(0.008, inputDt));
    }

    private bool UpdateCameraDynamics(double dt)
    {
        bool changed = false;
        if (!_dragging)
        {
            if (Math.Abs(_yawVelocity) > 0.02 || Math.Abs(_pitchVelocity) > 0.02)
            {
                _yaw += _yawVelocity * dt;
                _pitch = Math.Clamp(_pitch + _pitchVelocity * dt, -86, 86);
                double damping = Math.Exp(-4.8 * dt);
                _yawVelocity *= damping;
                _pitchVelocity *= damping;
                if (Math.Abs(_yawVelocity) < 0.02) _yawVelocity = 0;
                if (Math.Abs(_pitchVelocity) < 0.02) _pitchVelocity = 0;
                changed = true;
            }
        }

        if (!_panning && _panVelocity.Length > 0.002)
        {
            _target += _panVelocity * dt;
            _panVelocity *= Math.Exp(-6.4 * dt);
            if (_panVelocity.Length < 0.002) _panVelocity = new Vector3D();
            changed = true;
        }

        double distanceDelta = _targetDistance - _distance;
        if (Math.Abs(distanceDelta) > 0.002)
        {
            double factor = 1.0 - Math.Exp(-9.0 * dt);
            _distance += distanceDelta * factor;
            changed = true;
        }
        return changed;
    }

    private void ViewportHost_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        BuildStarfield();
        UpdateLabelPositions();
    }

    private void OrbitMotion_Click(object sender, RoutedEventArgs e)
    {
        _orbitMotionEnabled = !_orbitMotionEnabled;
        _lastOrbitTick = DateTime.UtcNow;
        UpdateOrbitButton();
        StatusText.Text = _orbitMotionEnabled ? "궤도 움직임 재생" : "궤도 움직임 일시정지";
    }

    private void UpdateOrbitButton()
    {
        if (OrbitMotionButton is not null)
            OrbitMotionButton.Content = _orbitMotionEnabled ? "궤도 이동: ON" : "궤도 이동: OFF";
    }

    private void SpeedDecrease_Click(object sender, RoutedEventArgs e)
    {
        double step = _speedPreset > 5.0 ? 1.0 : _speedPreset > 2.0 ? 0.5 : 0.1;
        SetSpeedPreset(_speedPreset - step);
    }

    private void SpeedIncrease_Click(object sender, RoutedEventArgs e)
    {
        double step = _speedPreset >= 5.0 ? 1.0 : _speedPreset >= 2.0 ? 0.5 : 0.1;
        SetSpeedPreset(_speedPreset + step);
    }

    private void SetSpeedPreset(double value)
    {
        _speedPreset = Math.Clamp(Math.Round(value, 1), 0.1, 10.0);
        if (SpeedSlider is not null) SpeedSlider.Value = _speedPreset;
        if (SpeedTextBox is not null) SpeedTextBox.Text = _speedPreset.ToString("0.0", CultureInfo.InvariantCulture);
        if (StatusText is not null) StatusText.Text = $"목표 공전 속도 {_speedPreset:0.0}× · 가속도 적용";
    }

    private void SpeedSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        _speedPreset = Math.Clamp(Math.Round(e.NewValue, 1), 0.1, 10.0);
        if (SpeedTextBox is not null && !SpeedTextBox.IsKeyboardFocusWithin)
            SpeedTextBox.Text = _speedPreset.ToString("0.0", CultureInfo.InvariantCulture);
        if (StatusText is not null)
            StatusText.Text = $"목표 공전 속도 {_speedPreset:0.0}× · 가속도 적용";
    }

    private void SpeedTextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        ApplySpeedText();
        Keyboard.ClearFocus();
        e.Handled = true;
    }

    private void SpeedTextBox_LostFocus(object sender, RoutedEventArgs e) => ApplySpeedText();

    private void ApplySpeedText()
    {
        if (SpeedTextBox is null) return;
        string raw = SpeedTextBox.Text.Trim().Replace(',', '.');
        if (!double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out double value))
            value = _speedPreset;
        SetSpeedPreset(value);
    }

    private void SyncSpeedControls()
    {
        if (SpeedSlider is not null) SpeedSlider.Value = _speedPreset;
        if (SpeedTextBox is not null) SpeedTextBox.Text = _speedPreset.ToString("0.0", CultureInfo.InvariantCulture);
    }

    private void LabelMode_Click(object sender, RoutedEventArgs e)
    {
        _labelMode = _labelMode switch
        {
            LabelMode.Auto => LabelMode.Major,
            LabelMode.Major => LabelMode.All,
            _ => LabelMode.Auto
        };
        UpdateLabelModeButton();
        UpdateLabelPositions();
    }

    private void UpdateLabelModeButton()
    {
        if (LabelModeButton is null) return;
        LabelModeButton.Content = _labelMode switch
        {
            LabelMode.Major => "라벨: 주요",
            LabelMode.All => "라벨: 전체",
            _ => "라벨: 자동"
        };
    }

    private bool ShouldShowLabel(LabelVisual label)
    {
        if (IsInfoHidden(label.Info)) return false;
        if (_selectedInfo is not null && Equals(_selectedInfo, label.Info)) return true;
        return _labelMode switch
        {
            LabelMode.All => true,
            LabelMode.Major => label.Important,
            _ => _results.Count <= 48 || label.Important
        };
    }

    private void UpdateLabelPositions()
    {
        if (LabelCanvas is null || TopologyViewport is null) return;
        double width = TopologyViewport.ActualWidth;
        double height = TopologyViewport.ActualHeight;
        if (width <= 1 || height <= 1) return;

        Vector3D forward = _camera.LookDirection;
        if (forward.Length < 0.0001) return;
        forward.Normalize();

        Vector3D up = _camera.UpDirection;
        if (up.Length < 0.0001) up = new Vector3D(0, 1, 0);
        up.Normalize();

        Vector3D right = Vector3D.CrossProduct(forward, up);
        if (right.Length < 0.0001) right = new Vector3D(1, 0, 0);
        right.Normalize();
        Vector3D trueUp = Vector3D.CrossProduct(right, forward);
        trueUp.Normalize();

        double aspect = width / height;
        double halfWidthFactor = Math.Tan(_camera.FieldOfView * Math.PI / 360.0);

        foreach (var label in _labels)
        {
            if (!ShouldShowLabel(label))
            {
                label.Element.Visibility = Visibility.Collapsed;
                continue;
            }

            Vector3D rel = label.Position - _camera.Position;
            double depth = Vector3D.DotProduct(rel, forward);
            if (depth <= _camera.NearPlaneDistance)
            {
                label.Element.Visibility = Visibility.Collapsed;
                continue;
            }

            double halfWidth = depth * halfWidthFactor;
            double halfHeight = halfWidth / Math.Max(0.01, aspect);
            if (halfWidth <= 0.0001 || halfHeight <= 0.0001)
            {
                label.Element.Visibility = Visibility.Collapsed;
                continue;
            }

            double x = Vector3D.DotProduct(rel, right);
            double y = Vector3D.DotProduct(rel, trueUp);
            double sx = width * 0.5 * (1.0 + x / halfWidth);
            double sy = height * 0.5 * (1.0 - y / halfHeight);

            if (sx < -140 || sx > width + 140 || sy < -90 || sy > height + 90)
            {
                label.Element.Visibility = Visibility.Collapsed;
                continue;
            }

            label.Element.Visibility = Visibility.Visible;
            label.Element.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
            var desired = label.Element.DesiredSize;
            Canvas.SetLeft(label.Element, sx - desired.Width / 2.0);
            Canvas.SetTop(label.Element, sy - desired.Height - 9.0);
            Panel.SetZIndex(label.Element, Math.Max(0, 100000 - (int)(depth * 100)));

            if (_selectedInfo is not null && Equals(_selectedInfo, label.Info))
            {
                label.Element.BorderBrush = new SolidColorBrush(Color.FromRgb(250, 216, 59));
                label.Element.BorderThickness = new Thickness(1.7);
                label.Element.Opacity = 1.0;
            }
            else
            {
                label.Element.BorderBrush = new SolidColorBrush(LabelAccent(label.Info.Type, label.Info.IsSynthetic));
                label.Element.BorderThickness = new Thickness(1.0);
                double baseOpacity = depth > _distance * 1.15 ? 0.70 : 0.94;
                label.Element.Opacity = IsInfoDimmed(label.Info) ? Math.Min(0.20, baseOpacity) : baseOpacity;
            }
        }
        UpdateTrafficFlowOverlay();
    }

    private void UpdateTrafficFlowOverlay()
    {
        if (TrafficOverlayCanvas is null) return;
        TrafficOverlayCanvas.Children.Clear();
        if (TopologyViewport.ActualWidth <= 1 || TopologyViewport.ActualHeight <= 1) return;

        // External observation history survives the LIVE activity window and is rendered in
        // lavender. It is separate from an explicit start/end audit session (amber).
        foreach (var flow in _topologySignificanceSnapshot.ExternalFlows
                     .OrderByDescending(f => f.Bytes)
                     .ThenByDescending(f => f.Packets)
                     .Take(72))
        {
            if (!TryGetTopologyPosition(flow.SourceIp, out var source3D) || !TryGetTopologyPosition(flow.DestinationIp, out var target3D))
                continue;
            if (!TryProjectToViewport(source3D, out var a, out _) || !TryProjectToViewport(target3D, out var b, out _))
                continue;

            double strength = Math.Clamp(Math.Log10(1.0 + flow.Bytes) / 8.0, 0.10, 0.70);
            byte alpha = (byte)Math.Clamp(36 + strength * 92, 36, 112);
            var historyLine = new Line
            {
                X1 = a.X, Y1 = a.Y, X2 = b.X, Y2 = b.Y,
                Stroke = new SolidColorBrush(Color.FromArgb(alpha, 171, 154, 214)),
                StrokeThickness = 0.7 + strength * 1.5,
                StrokeDashArray = new DoubleCollection { 2, 6 },
                SnapsToDevicePixels = true,
                IsHitTestVisible = false
            };
            TrafficOverlayCanvas.Children.Add(historyLine);
        }

        // Persistent audit trail: cumulative start~end communications are amber.
        foreach (var flow in _trafficAuditSnapshot.Flows.OrderByDescending(f => f.Bytes).ThenByDescending(f => f.Packets).Take(36))
        {
            if (IsExcludedSensorHostExternalFlow(flow.SourceIp, flow.DestinationIp)) continue;
            if (!TryGetTopologyPosition(flow.SourceIp, out var source3D) || !TryGetTopologyPosition(flow.DestinationIp, out var target3D))
                continue;
            if (!TryProjectToViewport(source3D, out var a, out _) || !TryProjectToViewport(target3D, out var b, out _))
                continue;

            double strength = Math.Clamp(Math.Log10(1.0 + flow.Bytes) / 8.0, 0.12, 0.72);
            byte alpha = (byte)Math.Clamp(38 + strength * 100, 38, 115);
            var historyLine = new Line
            {
                X1 = a.X, Y1 = a.Y, X2 = b.X, Y2 = b.Y,
                Stroke = new SolidColorBrush(Color.FromArgb(alpha, 235, 166, 62)),
                StrokeThickness = 0.7 + strength * 1.7,
                StrokeDashArray = new DoubleCollection { 2, 5 },
                SnapsToDevicePixels = true,
                IsHitTestVisible = false
            };
            TrafficOverlayCanvas.Children.Add(historyLine);

            // Direction marker: source -> destination. Keeping this small makes cumulative audit
            // paths readable without turning the topology into a dense diagram.
            double dx = b.X - a.X;
            double dy = b.Y - a.Y;
            double len = Math.Sqrt(dx * dx + dy * dy);
            if (len > 16)
            {
                double ux = dx / len;
                double uy = dy / len;
                double px = -uy;
                double py = ux;
                double t = 0.64;
                double cx = a.X + dx * t;
                double cy = a.Y + dy * t;
                double arrowSize = 3.3 + strength * 2.2;
                var arrow = new Polygon
                {
                    Fill = new SolidColorBrush(Color.FromArgb((byte)Math.Min(175, alpha + 45), 244, 183, 72)),
                    IsHitTestVisible = false,
                    Points = new PointCollection
                    {
                        new Point(cx + ux * arrowSize * 1.6, cy + uy * arrowSize * 1.6),
                        new Point(cx - ux * arrowSize + px * arrowSize, cy - uy * arrowSize + py * arrowSize),
                        new Point(cx - ux * arrowSize - px * arrowSize, cy - uy * arrowSize - py * arrowSize)
                    }
                };
                TrafficOverlayCanvas.Children.Add(arrow);
            }
        }

        // Security relationship overlay: the same packet metadata used by the packet tracer is
        // summarized as triage-oriented suspicious relations. Render above audit/history, below LIVE pulses.
        foreach (var flow in _securityRelationshipSnapshot.SuspiciousFlows
                     .OrderByDescending(f => f.RiskScore)
                     .ThenByDescending(f => f.Bytes)
                     .Take(48))
        {
            if (IsExcludedSensorHostExternalFlow(flow.SourceIp, flow.DestinationIp)) continue;
            if (!TryGetTopologyPosition(flow.SourceIp, out var source3D) || !TryGetTopologyPosition(flow.DestinationIp, out var target3D))
                continue;
            if (!TryProjectToViewport(source3D, out var a, out _) || !TryProjectToViewport(target3D, out var b, out _))
                continue;

            Color riskColor = GetSecurityColor(flow.RiskLevel);
            double strength = Math.Clamp(Math.Max(15, flow.RiskScore) / 100.0, 0.20, 1.0);
            byte alpha = (byte)Math.Clamp(90 + strength * 135, 90, 225);
            var riskLine = new Line
            {
                X1 = a.X, Y1 = a.Y, X2 = b.X, Y2 = b.Y,
                Stroke = new SolidColorBrush(Color.FromArgb(alpha, riskColor.R, riskColor.G, riskColor.B)),
                StrokeThickness = 1.2 + strength * 2.8,
                StrokeDashArray = flow.IsLongLived ? new DoubleCollection { 7, 3 } : null,
                SnapsToDevicePixels = true,
                IsHitTestVisible = false
            };
            TrafficOverlayCanvas.Children.Add(riskLine);

            double dx = b.X - a.X;
            double dy = b.Y - a.Y;
            double len = Math.Sqrt(dx * dx + dy * dy);
            if (len > 18)
            {
                double ux = dx / len;
                double uy = dy / len;
                double px = -uy;
                double py = ux;
                double t = 0.72;
                double cx = a.X + dx * t;
                double cy = a.Y + dy * t;
                double arrowSize = 4.0 + strength * 2.8;
                var arrow = new Polygon
                {
                    Fill = new SolidColorBrush(Color.FromArgb((byte)Math.Min(245, alpha + 20), riskColor.R, riskColor.G, riskColor.B)),
                    IsHitTestVisible = false,
                    Points = new PointCollection
                    {
                        new Point(cx + ux * arrowSize * 1.65, cy + uy * arrowSize * 1.65),
                        new Point(cx - ux * arrowSize + px * arrowSize, cy - uy * arrowSize + py * arrowSize),
                        new Point(cx - ux * arrowSize - px * arrowSize, cy - uy * arrowSize - py * arrowSize)
                    }
                };
                TrafficOverlayCanvas.Children.Add(arrow);
            }
        }

        if (_trafficSnapshot.Flows.Count == 0) return;
        double phase = (DateTime.UtcNow.TimeOfDay.TotalSeconds * 0.62) % 1.0;
        foreach (var flow in _trafficSnapshot.Flows.OrderByDescending(f => f.BytesPerSecond).Take(20))
        {
            if (IsExcludedSensorHostExternalFlow(flow.SourceIp, flow.DestinationIp)) continue;
            if (!TryGetTopologyPosition(flow.SourceIp, out var source3D) || !TryGetTopologyPosition(flow.DestinationIp, out var target3D))
                continue;
            if (!TryProjectToViewport(source3D, out var a, out _) || !TryProjectToViewport(target3D, out var b, out _))
                continue;

            double activity = Math.Max(flow.BytesPerSecond, flow.PacketsPerSecond * 96.0);
            double strength = Math.Clamp(Math.Log10(1.0 + activity) / 5.0, 0.18, 1.0);
            byte alpha = (byte)Math.Clamp(55 + strength * 145, 55, 200);
            var brush = new SolidColorBrush(Color.FromArgb(alpha, 98, 217, 166));
            var line = new Line
            {
                X1 = a.X, Y1 = a.Y, X2 = b.X, Y2 = b.Y,
                Stroke = brush,
                StrokeThickness = 0.8 + strength * 1.8,
                StrokeDashArray = new DoubleCollection { 4, 4 },
                SnapsToDevicePixels = true
            };
            TrafficOverlayCanvas.Children.Add(line);

            // Directional moving pulse. Different flows are phase-shifted by their endpoint hash.
            double hashPhase = (Math.Abs(HashCode.Combine(flow.SourceIp, flow.DestinationIp, flow.Protocol)) % 1000) / 1000.0;
            double p = (phase + hashPhase) % 1.0;
            double x = a.X + (b.X - a.X) * p;
            double y = a.Y + (b.Y - a.Y) * p;
            double dotSize = 3.5 + strength * 4.0;
            var pulse = new Ellipse
            {
                Width = dotSize,
                Height = dotSize,
                Fill = new SolidColorBrush(Color.FromArgb((byte)Math.Min(240, alpha + 35), 121, 236, 184)),
                IsHitTestVisible = false
            };
            Canvas.SetLeft(pulse, x - dotSize / 2.0);
            Canvas.SetTop(pulse, y - dotSize / 2.0);
            TrafficOverlayCanvas.Children.Add(pulse);
        }
    }

    private bool TryGetTopologyPosition(string ip, out Point3D position)
    {
        if (_orbitNodeByIp.TryGetValue(ip, out var node))
        {
            position = node.Position;
            return true;
        }

        if (!string.IsNullOrWhiteSpace(_gatewayAddress) && string.Equals(ip, _gatewayAddress, StringComparison.OrdinalIgnoreCase))
        {
            position = new Point3D(0, 0, 0);
            return true;
        }

        var gatewayResult = _results.FirstOrDefault(r => r.IsGateway);
        if (gatewayResult is not null && string.Equals(ip, gatewayResult.IpAddress, StringComparison.OrdinalIgnoreCase))
        {
            position = new Point3D(0, 0, 0);
            return true;
        }

        position = default;
        return false;
    }

    private bool TryProjectToViewport(Point3D world, out Point screen, out double depth)
    {
        screen = default;
        depth = 0;
        double width = TopologyViewport.ActualWidth;
        double height = TopologyViewport.ActualHeight;
        if (width <= 1 || height <= 1) return false;

        Vector3D forward = _camera.LookDirection;
        if (forward.LengthSquared < 0.000001) return false;
        forward.Normalize();
        Vector3D up = _camera.UpDirection;
        if (up.LengthSquared < 0.000001) up = new Vector3D(0, 1, 0);
        up.Normalize();
        Vector3D right = Vector3D.CrossProduct(forward, up);
        if (right.LengthSquared < 0.000001) return false;
        right.Normalize();
        Vector3D trueUp = Vector3D.CrossProduct(right, forward);
        trueUp.Normalize();

        Vector3D rel = world - _camera.Position;
        depth = Vector3D.DotProduct(rel, forward);
        if (depth <= _camera.NearPlaneDistance) return false;
        double halfWidthFactor = Math.Tan(_camera.FieldOfView * Math.PI / 360.0);
        double aspect = width / Math.Max(1.0, height);
        double halfWidth = depth * halfWidthFactor;
        double halfHeight = halfWidth / Math.Max(0.01, aspect);
        if (halfWidth <= 0.0001 || halfHeight <= 0.0001) return false;

        double x = Vector3D.DotProduct(rel, right);
        double y = Vector3D.DotProduct(rel, trueUp);
        double sx = width * 0.5 * (1.0 + x / halfWidth);
        double sy = height * 0.5 * (1.0 - y / halfHeight);
        if (sx < -80 || sx > width + 80 || sy < -80 || sy > height + 80) return false;
        screen = new Point(sx, sy);
        return true;
    }

    private void ShowNodeInfo(NodeInfo info)
    {
        SelectedTypeText.Text = info.Type.ToDisplayName();
        SelectedIpText.Text = string.IsNullOrWhiteSpace(info.Ip) ? "-" : info.Ip;
        SelectedHostText.Text = string.IsNullOrWhiteSpace(info.Host) ? info.Group : info.Host;
        OpenDetailButton.IsEnabled = info.Result is not null;
        UpdateSelectedTrafficInfo(info);
        StatusText.Text = info.Result is not null
            ? $"선택 · {info.Type.ToDisplayName()} · {info.Ip} · 클릭하면 상세 모달"
            : $"선택 · {info.Type.ToDisplayName()} · {info.Ip}";
    }

    private void UpdateSelectedTrafficInfo(NodeInfo? info)
    {
        if (SelectedTrafficText is null) return;
        if (info is null || string.IsNullOrWhiteSpace(info.Ip))
        {
            if (SelectedSecurityText is not null)
            {
                SelectedSecurityText.Text = "보안: 분석 대기";
                SelectedSecurityText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
            SelectedTrafficText.Text = "통신 기록 없음";
            SelectedTrafficText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            return;
        }

        if (SelectedSecurityText is not null)
        {
            var security = _securityRelationshipSnapshot.FindNode(info.Ip);
            if (security is null)
            {
                SelectedSecurityText.Text = _securityRelationshipSnapshot.HasData ? "보안: NORMAL · 현재 휴리스틱 경고 없음" : "보안: 분석 대기";
                SelectedSecurityText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
            else if (security.RiskScore >= 25)
            {
                string reason = security.Reasons.Count > 0 ? string.Join(" / ", security.Reasons.Take(3)) : "행동 이상 징후";
                SelectedSecurityText.Text = $"보안: {security.RiskLevel} {security.RiskScore}/100 · {reason} · DNS {security.DnsAnomalyText} · BL {security.BaselineText} · Beacon {security.BeaconText}";
                SelectedSecurityText.Foreground = new SolidColorBrush(GetSecurityColor(security.RiskLevel));
            }
            else
            {
                SelectedSecurityText.Text = $"보안: NORMAL {security.RiskScore}/100 · 외부 {security.ExternalPeerCount:N0} peer · DNS {security.DnsAnomalyText} · BL {security.BaselineText}";
                SelectedSecurityText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
        }

        var rows = _trafficAuditSnapshot.Flows
            .Where(f => string.Equals(f.SourceIp, info.Ip, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(f.DestinationIp, info.Ip, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.ConnectionStarts > 0)
            .ThenByDescending(f => f.Bytes)
            .Take(5)
            .ToArray();

        if (rows.Length == 0)
        {
            var observedRows = _externalObservationSnapshot.Flows
                .Where(f => string.Equals(f.SourceIp, info.Ip, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(f.DestinationIp, info.Ip, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.Bytes)
                .ThenByDescending(f => f.Packets)
                .Take(5)
                .ToArray();
            if (observedRows.Length > 0)
            {
                SelectedTrafficText.Text = string.Join(Environment.NewLine, observedRows.Select(flow =>
                {
                    bool outbound = string.Equals(flow.SourceIp, info.Ip, StringComparison.OrdinalIgnoreCase);
                    string other = outbound ? flow.DestinationIp : flow.SourceIp;
                    string arrow = outbound ? "→" : "←";
                    return $"{arrow} {other} · {flow.ServiceText} · {TrafficAuditFlowRecord.FormatBytes(flow.Bytes)} · {flow.Packets:N0} pkt";
                }));
                SelectedTrafficText.Foreground = new SolidColorBrush(Color.FromRgb(190, 173, 227));
            }
            else if (_trafficSnapshot.Nodes.TryGetValue(info.Ip, out var live) && live.IsActive)
            {
                SelectedTrafficText.Text = $"LIVE · {live.RateText} · {live.TotalPacketsPerSecond:0.#} pkt/s";
                SelectedTrafficText.Foreground = new SolidColorBrush(Color.FromRgb(98, 217, 166));
            }
            else
            {
                SelectedTrafficText.Text = "현재/기록 세션에서 관찰된 통신 없음";
                SelectedTrafficText.Foreground = new SolidColorBrush(Color.FromRgb(142, 142, 142));
            }
            return;
        }

        var lines = new List<string>(rows.Length);
        foreach (var flow in rows)
        {
            bool outbound = string.Equals(flow.SourceIp, info.Ip, StringComparison.OrdinalIgnoreCase);
            string other = outbound ? flow.DestinationIp : flow.SourceIp;
            string arrow = outbound ? "→" : "←";
            string start = flow.ConnectionStarts > 0 ? $" · 접속 {flow.ConnectionStarts:N0}" : string.Empty;
            lines.Add($"{arrow} {other} · {flow.ServiceText} · {flow.BytesText}{start}");
        }
        SelectedTrafficText.Text = string.Join(Environment.NewLine, lines);
        SelectedTrafficText.Foreground = new SolidColorBrush(Color.FromRgb(235, 184, 78));
    }

    private void UpdateExternalHistoryUi()
    {
        if (ExternalHistoryText is not null)
        {
            string baseText = _externalObservationSnapshot.Count > 0
                ? $"관찰 {_topologySignificanceSnapshot.ObservedNodeCount:N0} · 중요 표시 {_topologySignificanceSnapshot.RenderedNodeCount:N0} · 저중요 숨김 {_topologySignificanceSnapshot.SuppressedNodeCount:N0} · Flow {_topologySignificanceSnapshot.RenderedFlowCount:N0}/{_topologySignificanceSnapshot.ObservedFlowCount:N0}"
                : "관찰 이력 없음";
            string sensorExclusion = _excludeSensorHostConnections
                ? $" · 실행 PC 제외 {_topologySignificanceSnapshot.SensorHostSuppressedFlowCount:N0} Flow"
                : string.Empty;
            ExternalHistoryText.Text = _captureCoverageSnapshot.CanRenderObservedExternalTopology
                ? (_includeLowSignificanceExternal ? $"{baseText} · 전체 표시{sensorExclusion}" : $"{baseText}{sensorExclusion}")
                : $"{baseText} · 관계도 상세 숨김{sensorExclusion}";
            ExternalHistoryText.Foreground = new SolidColorBrush(_captureCoverageSnapshot.CanRenderObservedExternalTopology && _externalObservationSnapshot.Count > 0
                ? Color.FromRgb(190, 173, 227)
                : Color.FromRgb(125, 125, 125));
        }
        if (ExternalHistoryClearButton is not null)
            ExternalHistoryClearButton.IsEnabled = _externalObservationClear is not null && _externalObservationSnapshot.HasData;
    }

    private void UpdateCaptureCoverageUi()
    {
        if (SensorCoverageText is null) return;
        SensorCoverageText.Text = _captureCoverageSnapshot.CoverageStateText;
        SensorCoverageText.Foreground = new SolidColorBrush(_captureCoverageSnapshot.IsSpanVerified
            ? Color.FromRgb(98, 217, 166)
            : _captureCoverageSnapshot.Mode == PacketCaptureScopeMode.SpanTap
                ? Color.FromRgb(250, 216, 59)
                : Color.FromRgb(165, 165, 165));
        if (SensorCoverageDetailText is not null)
            SensorCoverageDetailText.Text = _captureCoverageSnapshot.TopologyPolicyText;
    }

    private void QueueExternalSceneRefreshIfNeeded()
    {
        bool visibilityChanged = _captureCoverageSnapshot.CanRenderObservedExternalTopology != _sceneExternalVisibilityEnabled;
        bool displayedSetChanged = !string.Equals(_topologySignificanceSnapshot.Signature, _sceneExternalSignature, StringComparison.Ordinal);
        if ((!visibilityChanged && !displayedSetChanged) || _externalSceneRefreshQueued || !IsLoaded) return;

        var now = DateTime.UtcNow;
        if ((now - _lastExternalSceneRefreshUtc).TotalMilliseconds < 900) return;

        // Do not rebuild 3D meshes while the operator is orbiting/panning/zooming. The traffic
        // timer keeps calling this method, so the pending node-set change is applied as soon as
        // the gesture has been idle for a short grace period.
        if (IsViewInteractionActive(now)) return;

        _externalSceneRefreshQueued = true;
        Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
        {
            _externalSceneRefreshQueued = false;
            if (!IsLoaded) return;
            RebuildTopologySignificance();
            bool stillChanged = _captureCoverageSnapshot.CanRenderObservedExternalTopology != _sceneExternalVisibilityEnabled ||
                                !string.Equals(_topologySignificanceSnapshot.Signature, _sceneExternalSignature, StringComparison.Ordinal);
            if (!stillChanged) return;

            var dispatchNow = DateTime.UtcNow;
            if (IsViewInteractionActive(dispatchNow)) return;

            BuildScene(resetView: false);
            _lastExternalSceneRefreshUtc = dispatchNow;
        }));
    }

    private void SensorGuide_Click(object sender, RoutedEventArgs e)
    {
        new SensorGuideWindow(_captureCoverageProvider ?? (() => _captureCoverageSnapshot)) { Owner = this }.ShowDialog();
    }

    private void ExternalDetailMode_Changed(object sender, RoutedEventArgs e)
    {
        if (ExternalIncludeLowSignificanceCheck is null) return;
        bool include = ExternalIncludeLowSignificanceCheck.IsChecked == true;
        if (_includeLowSignificanceExternal == include && _topologySignificanceSnapshot.ObservedNodeCount > 0) return;
        _includeLowSignificanceExternal = include;
        RebuildTopologySignificance();
        UpdateExternalHistoryUi();
        if (IsLoaded)
            BuildScene(resetView: false);
    }

    private void SensorHostConnectionVisibility_Changed(object sender, RoutedEventArgs e)
    {
        if (ExternalExcludeSensorHostConnectionsCheck is null) return;
        bool exclude = ExternalExcludeSensorHostConnectionsCheck.IsChecked == true;
        if (_excludeSensorHostConnections == exclude) return;

        _excludeSensorHostConnections = exclude;
        _sensorHostExclusionChanged?.Invoke(exclude);
        RebuildTopologySignificance();
        UpdateExternalHistoryUi();
        if (IsLoaded)
            BuildScene(resetView: false);
    }

    private void ExternalHistoryClear_Click(object sender, RoutedEventArgs e)
    {
        if (_externalObservationClear is null || !_externalObservationSnapshot.HasData) return;
        var answer = ThemedMessageBox.Show(
            $"현재까지 관찰한 외부/Public IP {_externalObservationSnapshot.Count:N0}개와 연결 이력을 지우시겠습니까?\n\n실제 스캔 대상으로 등록된 공인 IP는 유지됩니다. 캡처가 계속 중이면 새 외부 통신은 다시 기록됩니다.",
            "NetLoom · 외부 관찰 이력", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        _externalObservationClear();
        _externalObservationSnapshot = _externalObservationProvider?.Invoke() ?? ExternalObservationSnapshot.Empty;
        BuildScene(resetView: false);
        UpdateExternalHistoryUi();
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        ReloadResults();
        BuildScene(resetView: false);
        StatusText.Text = $"새로고침 완료 · ONLINE {_results.Count:N0}개 · 시점/궤도 위치 유지";
    }

    private void CategoryFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (FilterInfrastructureCheck is null) return;
        _highlightedCategories.Clear();
        if (FilterInfrastructureCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.Infrastructure);
        if (FilterSpecialCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.Special);
        if (FilterPeripheralCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.Peripheral);
        if (FilterEndpointCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.Endpoint);
        if (FilterOtherCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.Other);
        if (FilterExternalCheck.IsChecked == true) _highlightedCategories.Add(TopologyCategory.External);
        ApplyVisualFilters();
    }

    private void ResetCategoryFilter_Click(object sender, RoutedEventArgs e)
    {
        FilterInfrastructureCheck.IsChecked = false;
        FilterSpecialCheck.IsChecked = false;
        FilterPeripheralCheck.IsChecked = false;
        FilterEndpointCheck.IsChecked = false;
        FilterOtherCheck.IsChecked = false;
        FilterExternalCheck.IsChecked = false;
        _highlightedCategories.Clear();
        ApplyVisualFilters();
    }

    private void HideIsolated_Changed(object sender, RoutedEventArgs e)
    {
        _hideIsolated = HideIsolatedCheck?.IsChecked == true;
        ApplyVisualFilters();
    }

    private void RebuildRelationshipIndex()
    {
        _relatedIps.Clear();
        foreach (var node in _orbitNodes)
        {
            if (IsStrongInfrastructure(node.Info.Type) && !string.IsNullOrWhiteSpace(node.Info.Ip))
                _relatedIps.Add(node.Info.Ip);
            if (node.Parent is not null)
            {
                if (!string.IsNullOrWhiteSpace(node.Info.Ip)) _relatedIps.Add(node.Info.Ip);
                if (!string.IsNullOrWhiteSpace(node.Parent.Info.Ip)) _relatedIps.Add(node.Parent.Info.Ip);
            }
        }
    }

    private bool IsGatewayInfo(NodeInfo info) =>
        info.IsSynthetic || info.Result?.IsGateway == true ||
        (!string.IsNullOrWhiteSpace(_gatewayAddress) && string.Equals(info.Ip, _gatewayAddress, StringComparison.OrdinalIgnoreCase));

    private bool IsInfoHidden(NodeInfo info)
    {
        if (!_hideIsolated || IsGatewayInfo(info) || info.Result is null) return false;
        return !_relatedIps.Contains(info.Ip);
    }

    private bool IsInfoDimmed(NodeInfo info)
    {
        if (IsGatewayInfo(info) || _highlightedCategories.Count == 0) return false;
        return !_highlightedCategories.Contains(info.Type.ToTopologyCategory());
    }

    private void ApplyVisualFilters()
    {
        foreach (var entry in _nodeVisuals)
        {
            double opacity = IsInfoHidden(entry.Info) ? 0.0 : IsInfoDimmed(entry.Info) ? 0.12 : 1.0;
            SetMaterialOpacity(entry.Model.Material, opacity);
            if (entry.Model.BackMaterial is not null && !ReferenceEquals(entry.Model.BackMaterial, entry.Model.Material))
                SetMaterialOpacity(entry.Model.BackMaterial, opacity);
        }

        foreach (var ring in _orbitRingVisuals)
        {
            var category = CategoryForBand(ring.Band);
            ring.Brush.Opacity = _highlightedCategories.Count == 0 || _highlightedCategories.Contains(category) ? 0.64 : 0.08;
        }

        foreach (var ring in _satelliteRings)
            ring.Brush.Opacity = _highlightedCategories.Count == 0 || _highlightedCategories.Contains(TopologyCategory.Endpoint) ? 0.62 : 0.08;

        UpdateLabelPositions();
    }

    private static void SetMaterialOpacity(Material material, double opacity)
    {
        switch (material)
        {
            case MaterialGroup group:
                foreach (var child in group.Children) SetMaterialOpacity(child, opacity);
                break;
            case DiffuseMaterial diffuse when diffuse.Brush is not null:
                diffuse.Brush.Opacity = opacity;
                break;
            case SpecularMaterial specular when specular.Brush is not null:
                specular.Brush.Opacity = opacity;
                break;
            case EmissiveMaterial emissive when emissive.Brush is not null:
                emissive.Brush.Opacity = opacity;
                break;
        }
    }

    private static TopologyCategory CategoryForBand(OrbitBand band) => band switch
    {
        OrbitBand.Infrastructure => TopologyCategory.Infrastructure,
        OrbitBand.Special => TopologyCategory.Special,
        OrbitBand.Peripheral => TopologyCategory.Peripheral,
        OrbitBand.Endpoint => TopologyCategory.Endpoint,
        OrbitBand.External => TopologyCategory.External,
        _ => TopologyCategory.Other
    };

    private void AddGatewayHalo(Point3D center)
    {
        var mesh = CreateSphereMesh(new Point3D(0, 0, 0), 1.18, 24, 18);
        var brush = new SolidColorBrush(Color.FromRgb(250, 216, 59)) { Opacity = 0.12 };
        var material = new EmissiveMaterial(brush);
        var scale = new ScaleTransform3D(1, 1, 1);
        var transform = new Transform3DGroup();
        transform.Children.Add(scale);
        transform.Children.Add(new TranslateTransform3D(center.X, center.Y, center.Z));
        var model = new GeometryModel3D(mesh, material)
        {
            BackMaterial = material,
            Transform = transform
        };
        TopologyViewport.Children.Add(new ModelVisual3D { Content = model });
        _gatewayHalos.Add(new GatewayHaloVisual { Scale = scale, Brush = brush });
    }

    private void UpdateGatewayHalo()
    {
        if (_gatewayHalos.Count == 0) return;
        double phase = DateTime.UtcNow.TimeOfDay.TotalSeconds * 1.6;
        double pulse = 1.0 + 0.065 * (0.5 + 0.5 * Math.Sin(phase));
        double opacity = 0.09 + 0.055 * (0.5 + 0.5 * Math.Sin(phase));
        foreach (var halo in _gatewayHalos)
        {
            halo.Scale.ScaleX = pulse;
            halo.Scale.ScaleY = pulse;
            halo.Scale.ScaleZ = pulse;
            halo.Brush.Opacity = opacity;
        }
    }

    private void BuildStarfield()
    {
        if (StarfieldCanvas is null || ViewportHost is null) return;
        double width = Math.Max(1, ViewportHost.ActualWidth);
        double height = Math.Max(1, ViewportHost.ActualHeight);
        if (width < 20 || height < 20) return;

        StarfieldCanvas.Children.Clear();
        int count = Math.Clamp((int)(width * height / 7000.0), 90, 260);
        var random = new Random(41827);
        for (int i = 0; i < count; i++)
        {
            double size = i % 17 == 0 ? 2.2 : i % 5 == 0 ? 1.45 : 0.9;
            var star = new Ellipse
            {
                Width = size,
                Height = size,
                Fill = new SolidColorBrush(i % 11 == 0 ? Color.FromRgb(196, 211, 235) : Color.FromRgb(222, 224, 228)),
                Opacity = 0.24 + random.NextDouble() * 0.58,
                IsHitTestVisible = false
            };
            Canvas.SetLeft(star, random.NextDouble() * Math.Max(1, width - size));
            Canvas.SetTop(star, random.NextDouble() * Math.Max(1, height - size));
            StarfieldCanvas.Children.Add(star);
        }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Maximize_Click(object sender, RoutedEventArgs e) => ToggleMaximize();
    private void ToggleMaximize() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void OpenDetail_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedInfo?.Result is ScanResult result)
            OpenDeviceDetail(result);
    }

    private void OpenDeviceDetail(ScanResult result)
    {
        if (_deviceDetailOpen) return;

        try
        {
            _deviceDetailOpen = true;
            var detail = new DeviceDetailWindow(result, _securityRelationshipSnapshot.FindNode(result.IpAddress)) { Owner = this };
            detail.ShowDialog();
        }
        finally
        {
            _deviceDetailOpen = false;
        }
    }

    private Dictionary<string, OrbitMotionState> CaptureOrbitMotionState()
    {
        var state = new Dictionary<string, OrbitMotionState>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in _orbitNodes)
        {
            string key = BuildNodeStateKey(node.Info);
            if (string.IsNullOrWhiteSpace(key)) continue;
            state[key] = new OrbitMotionState(node.CurrentAngle, node.CurrentAngularSpeed);
        }
        return state;
    }

    private void RestoreOrbitMotionState(IReadOnlyDictionary<string, OrbitMotionState> state)
    {
        if (state.Count == 0) return;

        foreach (var node in _orbitNodes)
        {
            string key = BuildNodeStateKey(node.Info);
            if (!state.TryGetValue(key, out var saved)) continue;
            node.CurrentAngle = saved.CurrentAngle;
            node.CurrentAngularSpeed = saved.CurrentAngularSpeed;
        }

        // Recalculate positions parent-first after restoring phase. Without this, an automatic
        // External/Public scene rebuild starts every planet again at its original base angle.
        foreach (var node in _orbitNodes.Where(n => !n.IsSatellite))
            UpdateNodeOrbit(node, 0, null);
        foreach (var node in _orbitNodes.Where(n => n.IsSatellite))
            UpdateNodeOrbit(node, 0, node.Parent?.Position);

        foreach (var ring in _satelliteRings)
        {
            var p = ring.Parent.Position;
            ring.Translation.OffsetX = p.X;
            ring.Translation.OffsetY = p.Y;
            ring.Translation.OffsetZ = p.Z;
        }
    }

    private SceneViewState CaptureSceneViewState() => new(
        _yaw,
        _pitch,
        _distance,
        _targetDistance,
        _target,
        _yawVelocity,
        _pitchVelocity,
        _panVelocity,
        _motionSpeedFactor,
        _selectedInfo is null ? null : BuildNodeStateKey(_selectedInfo));

    private void RestoreSceneViewState(SceneViewState? state)
    {
        if (state is null) return;

        _yaw = state.Yaw;
        _pitch = state.Pitch;
        _distance = state.Distance;
        _targetDistance = state.TargetDistance;
        _target = state.Target;
        _yawVelocity = state.YawVelocity;
        _pitchVelocity = state.PitchVelocity;
        _panVelocity = state.PanVelocity;
        _motionSpeedFactor = state.MotionSpeedFactor;

        if (!string.IsNullOrWhiteSpace(state.SelectedNodeKey))
        {
            _selectedInfo = _modelInfo.Values.FirstOrDefault(info =>
                string.Equals(BuildNodeStateKey(info), state.SelectedNodeKey, StringComparison.OrdinalIgnoreCase));
            if (_selectedInfo is not null)
                ShowNodeInfo(_selectedInfo);
        }
    }

    private static string BuildNodeStateKey(NodeInfo info)
    {
        if (!string.IsNullOrWhiteSpace(info.Ip) && !info.IsSynthetic)
            return $"IP|{info.Ip.Trim()}";

        return $"SYN|{(int)info.Type}|{info.Ip.Trim()}|{info.Host.Trim()}|{info.Group.Trim()}";
    }

    private bool IsViewInteractionActive(DateTime now)
    {
        if (_dragging || _panning || Mouse.Captured == ViewportInputSurface)
            return true;
        return (now - _lastMouseInput).TotalMilliseconds < 350;
    }

    private void ResetView_Click(object sender, RoutedEventArgs e) => ResetCamera();

    private void TopView_Click(object sender, RoutedEventArgs e)
    {
        _yaw = -90;
        _pitch = 79;
        _distance = Math.Clamp(Math.Max(42, _sceneRadius * 2.05 + Math.Sqrt(Math.Max(1, _results.Count)) * 0.65), 42, 220);
        _targetDistance = _distance;
        _yawVelocity = 0;
        _pitchVelocity = 0;
        _panVelocity = new Vector3D();
        UpdateCamera();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ResetCamera()
    {
        _yaw = -42;
        _pitch = 27;
        _distance = Math.Clamp(Math.Max(42, _sceneRadius * 2.12 + Math.Sqrt(Math.Max(1, _results.Count)) * 0.72), 42, 230);
        _targetDistance = _distance;
        _target = new Point3D(0, 0.2, 0);
        _yawVelocity = 0;
        _pitchVelocity = 0;
        _panVelocity = new Vector3D();
        UpdateCamera();
    }

    private void UpdateCamera()
    {
        double yaw = _yaw * Math.PI / 180.0;
        double pitch = _pitch * Math.PI / 180.0;
        double cp = Math.Cos(pitch);
        var pos = new Point3D(
            _target.X + _distance * cp * Math.Cos(yaw),
            _target.Y + _distance * Math.Sin(pitch),
            _target.Z + _distance * cp * Math.Sin(yaw));

        _camera.Position = pos;
        _camera.LookDirection = _target - pos;
        _camera.UpDirection = new Vector3D(0, 1, 0);
        _camera.FieldOfView = 48;
        _camera.NearPlaneDistance = 0.1;
        _camera.FarPlaneDistance = 800;
        UpdateLabelPositions();
    }

    private static string BuildLabelTitle(NodeInfo info)
    {
        if (info.Type == DeviceType.Internet) return string.IsNullOrWhiteSpace(info.Ip) ? "Internet / Public" : $"External · {info.Ip}";
        if (info.IsSynthetic && info.Host == "감사 대역") return info.Ip;
        if (info.IsSynthetic && info.Host == "하위 네트워크") return $"하위망 · {info.Ip}";
        string ip = string.IsNullOrWhiteSpace(info.Ip) ? "-" : info.Ip;
        return $"{info.Type.ToDisplayName()} · {ip}";
    }

    private static string BuildLabelSecondary(NodeInfo info)
    {
        if (info.IsSynthetic && info.Host == "감사 대역") return string.IsNullOrWhiteSpace(info.Group) ? "감사 대역" : info.Group;
        if (info.IsSynthetic && info.Host == "하위 네트워크") return string.IsNullOrWhiteSpace(info.Group) ? "경로 확인 필요" : info.Group;
        if (string.IsNullOrWhiteSpace(info.Host)) return string.IsNullOrWhiteSpace(info.Group) ? string.Empty : info.Group;
        return Shorten(info.Host.Split('.')[0], 30);
    }

    private static string Shorten(string value, int max)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= max) return value;
        return value[..Math.Max(1, max - 1)] + "…";
    }

    private static Color LabelAccent(DeviceType type, bool synthetic)
    {
        if (synthetic) return Color.FromRgb(154, 132, 40);
        return type switch
        {
            DeviceType.Server => Color.FromRgb(117, 153, 211),
            DeviceType.Nas => Color.FromRgb(82, 177, 164),
            DeviceType.Hypervisor => Color.FromRgb(145, 126, 196),
            DeviceType.Printer => Color.FromRgb(190, 190, 190),
            DeviceType.Router or DeviceType.Switch or DeviceType.Hub or DeviceType.AccessPoint or DeviceType.WifiExtender or DeviceType.Firewall => Color.FromRgb(190, 163, 44),
            DeviceType.Internet => Color.FromRgb(170, 156, 204),
            _ => Color.FromRgb(76, 76, 76)
        };
    }

    private static OrbitBand BandFor(DeviceType type) => type switch
    {
        DeviceType.Router or DeviceType.Switch or DeviceType.Hub or DeviceType.AccessPoint or DeviceType.WifiExtender or DeviceType.Firewall => OrbitBand.Infrastructure,
        DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor => OrbitBand.Special,
        DeviceType.Printer or DeviceType.Camera or DeviceType.Ups or DeviceType.VoipPhone => OrbitBand.Peripheral,
        DeviceType.Pc or DeviceType.Mobile or DeviceType.IoT => OrbitBand.Endpoint,
        _ => OrbitBand.Other
    };

    private static double BandBaseRadius(OrbitBand band) => band switch
    {
        OrbitBand.Infrastructure => 4.8,
        OrbitBand.Special => 7.5,
        OrbitBand.Peripheral => 10.4,
        OrbitBand.Endpoint => 13.4,
        OrbitBand.Other => 16.2,
        _ => 19.0
    };

    private static double BandInclinationDegrees(OrbitBand band) => band switch
    {
        OrbitBand.Infrastructure => -6,
        OrbitBand.Special => 10,
        OrbitBand.Peripheral => -15,
        OrbitBand.Endpoint => 21,
        OrbitBand.Other => -25,
        _ => 30
    };

    private static double GroupInclinationDegrees(int groupIndex)
    {
        double[] values = { -12, 9, 24, -28, 36, -40, 17 };
        return values[groupIndex % values.Length];
    }

    private static double BaseSpeedFor(OrbitBand band, double radius)
    {
        double baseSpeed = band switch
        {
            OrbitBand.Infrastructure => 0.046,
            OrbitBand.Special => 0.052,
            OrbitBand.Peripheral => 0.060,
            OrbitBand.Endpoint => 0.068,
            OrbitBand.Other => 0.056,
            _ => 0.032
        };
        return baseSpeed / Math.Sqrt(Math.Max(1.0, radius / 4.0));
    }

    private static double NodeSizeFor(DeviceType type, OrbitBand band)
    {
        if (type is DeviceType.Router or DeviceType.Firewall) return 0.44;
        if (type is DeviceType.Switch or DeviceType.Hub) return 0.40;
        if (type is DeviceType.AccessPoint or DeviceType.WifiExtender) return 0.37;
        if (type is DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor) return 0.38;
        if (type is DeviceType.Printer or DeviceType.Camera or DeviceType.Ups) return 0.32;
        if (type == DeviceType.VoipPhone) return 0.28;
        return band == OrbitBand.Other ? 0.25 : 0.23;
    }

    private static Color OrbitColor(OrbitBand band) => band switch
    {
        OrbitBand.Infrastructure => Color.FromArgb(126, 155, 133, 47),
        OrbitBand.Special => Color.FromArgb(116, 75, 104, 144),
        OrbitBand.Peripheral => Color.FromArgb(108, 128, 128, 130),
        OrbitBand.Endpoint => Color.FromArgb(92, 91, 91, 94),
        OrbitBand.Other => Color.FromArgb(96, 112, 92, 125),
        _ => Color.FromArgb(112, 132, 118, 164)
    };

    private static Color NodeColorFor(DeviceType type, OrbitBand band) => type switch
    {
        DeviceType.Router => Color.FromRgb(250, 216, 59),
        DeviceType.Firewall => Color.FromRgb(229, 177, 51),
        DeviceType.Switch or DeviceType.Hub => Color.FromRgb(214, 190, 73),
        DeviceType.AccessPoint => Color.FromRgb(200, 180, 80),
        DeviceType.WifiExtender => Color.FromRgb(174, 196, 111),
        DeviceType.Server => Color.FromRgb(117, 153, 211),
        DeviceType.Nas => Color.FromRgb(82, 177, 164),
        DeviceType.Hypervisor => Color.FromRgb(145, 126, 196),
        DeviceType.Printer => Color.FromRgb(205, 205, 205),
        DeviceType.Camera => Color.FromRgb(171, 185, 201),
        DeviceType.Ups => Color.FromRgb(194, 168, 118),
        DeviceType.VoipPhone => Color.FromRgb(126, 174, 199),
        DeviceType.Mobile => Color.FromRgb(112, 145, 170),
        DeviceType.IoT => Color.FromRgb(126, 158, 134),
        DeviceType.Internet => Color.FromRgb(190, 170, 225),
        DeviceType.NetworkDevice => Color.FromRgb(139, 116, 154),
        DeviceType.Unknown => Color.FromRgb(118, 102, 128),
        _ => band == OrbitBand.External ? Color.FromRgb(170, 156, 204) : Color.FromRgb(128, 128, 132)
    };

    private static double Degrees(double value) => value * Math.PI / 180.0;

    private static MeshGeometry3D CreateOrbitRingMesh(
        double semiMajorAxis,
        double inclination,
        double ascendingNode,
        double eccentricity,
        double halfThickness,
        int segments)
    {
        var mesh = new MeshGeometry3D();
        double inner = Math.Max(0.1, semiMajorAxis - halfThickness);
        double outer = semiMajorAxis + halfThickness;
        for (int i = 0; i <= segments; i++)
        {
            double angle = Math.PI * 2 * i / segments;
            var a = OrbitVector(inner, angle, inclination, ascendingNode, eccentricity);
            var b = OrbitVector(outer, angle, inclination, ascendingNode, eccentricity);
            mesh.Positions.Add(new Point3D(a.X, a.Y, a.Z));
            mesh.Positions.Add(new Point3D(b.X, b.Y, b.Z));
        }

        for (int i = 0; i < segments; i++)
        {
            int a = i * 2;
            int b = a + 1;
            int c = a + 2;
            int d = a + 3;
            mesh.TriangleIndices.Add(a); mesh.TriangleIndices.Add(b); mesh.TriangleIndices.Add(c);
            mesh.TriangleIndices.Add(c); mesh.TriangleIndices.Add(b); mesh.TriangleIndices.Add(d);
        }
        return mesh;
    }

    private static MeshGeometry3D CreateSphereMesh(Point3D center, double radius, int slices, int stacks)
    {
        var mesh = new MeshGeometry3D();
        for (int stack = 0; stack <= stacks; stack++)
        {
            double phi = Math.PI * stack / stacks;
            double y = Math.Cos(phi);
            double rr = Math.Sin(phi);
            for (int slice = 0; slice <= slices; slice++)
            {
                double theta = Math.PI * 2 * slice / slices;
                var n = new Vector3D(rr * Math.Cos(theta), y, rr * Math.Sin(theta));
                mesh.Positions.Add(center + n * radius);
                mesh.Normals.Add(n);
            }
        }

        int stride = slices + 1;
        for (int stack = 0; stack < stacks; stack++)
        for (int slice = 0; slice < slices; slice++)
        {
            int a = stack * stride + slice;
            int b = a + stride;
            mesh.TriangleIndices.Add(a); mesh.TriangleIndices.Add(b); mesh.TriangleIndices.Add(a + 1);
            mesh.TriangleIndices.Add(a + 1); mesh.TriangleIndices.Add(b); mesh.TriangleIndices.Add(b + 1);
        }
        return mesh;
    }

    private static MeshGeometry3D CreateBoxMesh(Point3D center, double halfX, double halfY, double halfZ, bool diamond)
    {
        var mesh = new MeshGeometry3D();
        AppendBox(mesh, center, halfX, halfY, halfZ, diamond);
        return mesh;
    }

    private static MeshGeometry3D CreatePrinterMesh(Point3D center, double size)
    {
        var mesh = new MeshGeometry3D();
        AppendBox(mesh, center + new Vector3D(0, -size * 0.12, 0), size * 1.08, size * 0.58, size * 0.92, false);
        AppendBox(mesh, center + new Vector3D(0, size * 0.55, -size * 0.08), size * 0.68, size * 0.32, size * 0.62, false);
        return mesh;
    }

    private static void AppendBox(MeshGeometry3D mesh, Point3D center, double halfX, double halfY, double halfZ, bool diamond)
    {
        var pts = new[]
        {
            new Point3D(-halfX,-halfY,-halfZ), new Point3D(halfX,-halfY,-halfZ), new Point3D(halfX,halfY,-halfZ), new Point3D(-halfX,halfY,-halfZ),
            new Point3D(-halfX,-halfY, halfZ), new Point3D(halfX,-halfY, halfZ), new Point3D(halfX,halfY, halfZ), new Point3D(-halfX,halfY, halfZ)
        };
        if (diamond)
        {
            var rot = new RotateTransform3D(new AxisAngleRotation3D(new Vector3D(0, 1, 0), 45));
            for (int i = 0; i < pts.Length; i++) pts[i] = rot.Transform(pts[i]);
        }

        int offset = mesh.Positions.Count;
        foreach (var p in pts) mesh.Positions.Add(center + new Vector3D(p.X, p.Y, p.Z));
        int[] triangles = { 0,2,1, 0,3,2, 4,5,6, 4,6,7, 0,1,5, 0,5,4, 3,7,6, 3,6,2, 1,2,6, 1,6,5, 0,4,7, 0,7,3 };
        foreach (int i in triangles) mesh.TriangleIndices.Add(offset + i);
    }

    private static bool IsStrongInfrastructure(DeviceType type) => type is
        DeviceType.Router or DeviceType.Switch or DeviceType.Hub or DeviceType.AccessPoint or DeviceType.WifiExtender or DeviceType.Firewall;

    private static bool IsSpecialAsset(DeviceType type) => type is
        DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor or DeviceType.Printer;

    private bool IsExcludedSensorHostExternalFlow(string sourceIp, string destinationIp)
    {
        if (!_excludeSensorHostConnections || string.IsNullOrWhiteSpace(_captureCoverageSnapshot.AdapterAddress)) return false;
        string sensorIp = _captureCoverageSnapshot.AdapterAddress;
        return (string.Equals(sourceIp, sensorIp, StringComparison.OrdinalIgnoreCase) && IsPublicIpv4(destinationIp)) ||
               (string.Equals(destinationIp, sensorIp, StringComparison.OrdinalIgnoreCase) && IsPublicIpv4(sourceIp));
    }

    private static bool IsPublicIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return false;
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return false;
        if (b[0] == 10) return false;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
        if (b[0] == 192 && b[1] == 168) return false;
        if (b[0] == 127) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
        if (b[0] == 0 || b[0] >= 224) return false;
        return true;
    }
}
