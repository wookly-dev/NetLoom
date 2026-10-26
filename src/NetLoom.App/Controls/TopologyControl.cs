using System.Globalization;
using System.Net;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using NetLoom.App.Models;
using NetLoom.App.Services;

namespace NetLoom.App.Controls;

public sealed class TopologyControl : FrameworkElement
{
    private readonly List<ScanResult> _results = new();
    private readonly List<(Rect Bounds, ScanResult Result)> _hitRegions = new();
    private string _gatewayAddress = "";
    private readonly HashSet<TopologyCategory> _highlightedCategories = new();
    private readonly List<NestedNetworkInfo> _nestedNetworks = new();
    private readonly Dictionary<string, Point> _nodeCenters = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Point> _groupAnchors = new(StringComparer.OrdinalIgnoreCase);
    private TrafficSnapshot _trafficSnapshot = TrafficSnapshot.Empty;
    private TrafficAuditSessionSnapshot _trafficAuditSnapshot = TrafficAuditSessionSnapshot.Empty;
    private ExternalObservationSnapshot _externalObservationSnapshot = ExternalObservationSnapshot.Empty;
    private SecurityRelationshipSnapshot _securityRelationshipSnapshot = SecurityRelationshipSnapshot.Empty;
    private CaptureCoverageSnapshot _captureCoverageSnapshot = CaptureCoverageSnapshot.Empty;
    private TopologySignificanceSnapshot _topologySignificanceSnapshot = TopologySignificanceSnapshot.Empty;
    private bool _includeLowSignificanceExternal;
    private bool _excludeSensorHostConnections;
    private readonly List<TopologyRootNetwork> _topologyRoots = new();

    public event Action<ScanResult>? DeviceNodeClicked;
    private bool _lightTheme;
    private bool _perspectiveMode;

    public bool AutoSizeCanvas { get; set; } = true;

    public Size RecommendedCanvasSize { get; private set; } = new(1500, 800);

    public bool LightTheme
    {
        get => _lightTheme;
        set
        {
            if (_lightTheme == value) return;
            _lightTheme = value;
            InvalidateVisual();
        }
    }

    public bool PerspectiveMode
    {
        get => _perspectiveMode;
        set
        {
            if (_perspectiveMode == value) return;
            _perspectiveMode = value;
            InvalidateVisual();
        }
    }

    public void SetHighlightedCategories(IEnumerable<TopologyCategory> categories)
    {
        _highlightedCategories.Clear();
        foreach (var category in categories.Distinct())
            _highlightedCategories.Add(category);
        InvalidateVisual();
    }

    public void SetNestedNetworks(IEnumerable<NestedNetworkInfo> nestedNetworks)
    {
        _nestedNetworks.Clear();
        _nestedNetworks.AddRange(nestedNetworks ?? Array.Empty<NestedNetworkInfo>());
        InvalidateVisual();
    }

    public void SetTrafficSnapshot(TrafficSnapshot snapshot)
    {
        _trafficSnapshot = snapshot ?? TrafficSnapshot.Empty;
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetTrafficAuditSnapshot(TrafficAuditSessionSnapshot snapshot)
    {
        _trafficAuditSnapshot = snapshot ?? TrafficAuditSessionSnapshot.Empty;
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetExternalObservationSnapshot(ExternalObservationSnapshot snapshot)
    {
        _externalObservationSnapshot = snapshot ?? ExternalObservationSnapshot.Empty;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetSecurityRelationshipSnapshot(SecurityRelationshipSnapshot snapshot)
    {
        _securityRelationshipSnapshot = snapshot ?? SecurityRelationshipSnapshot.Empty;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetCaptureCoverageSnapshot(CaptureCoverageSnapshot snapshot)
    {
        _captureCoverageSnapshot = snapshot ?? CaptureCoverageSnapshot.Empty;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetIncludeLowSignificanceExternal(bool include)
    {
        if (_includeLowSignificanceExternal == include) return;
        _includeLowSignificanceExternal = include;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetExcludeSensorHostConnections(bool exclude)
    {
        if (_excludeSensorHostConnections == exclude) return;
        _excludeSensorHostConnections = exclude;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
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

    public void SetTopologyAnalysisContext(
        ExternalObservationSnapshot external,
        SecurityRelationshipSnapshot security,
        CaptureCoverageSnapshot coverage)
    {
        _externalObservationSnapshot = external ?? ExternalObservationSnapshot.Empty;
        _securityRelationshipSnapshot = security ?? SecurityRelationshipSnapshot.Empty;
        _captureCoverageSnapshot = coverage ?? CaptureCoverageSnapshot.Empty;
        RebuildTopologySignificance();
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    public void SetTopologyRoots(IEnumerable<TopologyRootNetwork> roots)
    {
        _topologyRoots.Clear();
        _topologyRoots.AddRange(roots ?? Array.Empty<TopologyRootNetwork>());
        InvalidateVisual();
    }

    private bool IsDimmed(DeviceType type) =>
        _highlightedCategories.Count > 0 && !_highlightedCategories.Contains(type.ToTopologyCategory());

    public void SetData(IEnumerable<ScanResult> results, string gatewayAddress)
    {
        _results.Clear();
        _results.AddRange(results.Where(r => r.IsOnline));
        _gatewayAddress = gatewayAddress ?? "";
        UpdateRecommendedCanvasSize();
        InvalidateVisual();
    }

    private void UpdateRecommendedCanvasSize()
    {
        int externalCount = GetExternalDisplayResults().Count;
        RecommendedCanvasSize = CalculateRecommendedSize(_results, externalCount);
        if (AutoSizeCanvas)
        {
            Width = RecommendedCanvasSize.Width;
            Height = RecommendedCanvasSize.Height;
        }
    }

    private static Size CalculateRecommendedSize(IReadOnlyList<ScanResult> results, int externalCount)
    {
        var local = results.Where(r => !IsPublicIpv4(r.IpAddress)).ToList();
        var groups = local
            .GroupBy(r => string.IsNullOrWhiteSpace(r.AuditGroupLabel) ? "감사 대역" : r.AuditGroupLabel)
            .Select(g => (IReadOnlyList<ScanResult>)g.ToList())
            .ToList();

        const double canvasWidth = 1680;
        const double nodeCellWidth = 116;
        const double nodeCellHeight = 78;
        const double panelInnerWidth = canvasWidth - 190;
        int columns = Math.Max(6, (int)Math.Floor(panelInnerWidth / nodeCellWidth));

        double height = 205;
        if (externalCount > 0)
            height += 150 + Math.Ceiling(externalCount / (double)columns) * nodeCellHeight;

        foreach (var groupItems in groups)
            height += CalculateGroupPanelHeight(groupItems, canvasWidth) + 24;

        height += 70;
        return new Size(canvasWidth, Math.Max(760, height));
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);

        _hitRegions.Clear();
        _nodeCenters.Clear();
        _groupAnchors.Clear();
        double w = Math.Max(1, ActualWidth);
        double h = Math.Max(1, ActualHeight);

        var bg = BrushRgb(LightTheme ? (255, 255, 255) : (23, 23, 23));
        var panelFill = BrushRgb(LightTheme ? (249, 249, 249) : (27, 27, 27));
        var panelAlt = BrushRgb(LightTheme ? (244, 244, 244) : (31, 31, 31));
        var border = new Pen(BrushRgb(LightTheme ? (210, 210, 210) : (53, 53, 53)), 1);
        var endpointLine = new Pen(BrushRgb(LightTheme ? (202, 202, 202) : (62, 62, 62)), 1.0);
        var inferredLine = new Pen(BrushRgb(LightTheme ? (176, 176, 176) : (82, 82, 82)), 1.05)
        {
            DashStyle = DashStyles.Dash
        };
        var branchLine = new Pen(BrushRgb(LightTheme ? (181, 168, 103) : (78, 73, 44)), 1.5);
        var trunkLine = new Pen(BrushRgb(LightTheme ? (158, 132, 0) : (119, 103, 33)), 2.0);
        var accent = BrushRgb(LightTheme ? (158, 132, 0) : (250, 216, 59));
        var text = BrushRgb(LightTheme ? (35, 35, 35) : (226, 226, 226));
        var muted = BrushRgb(LightTheme ? (100, 100, 100) : (138, 138, 138));
        var subtle = BrushRgb(LightTheme ? (132, 132, 132) : (102, 102, 102));

        dc.DrawRoundedRectangle(bg, border, new Rect(0.5, 0.5, w - 1, h - 1), 6, 6);
        DrawText(dc, "감사 네트워크 관계도", 14, FontWeights.SemiBold, text, new Point(14, 12));
        DrawText(dc,
            "실선 = 확인 가능한 감사 범위/게이트웨이 구조 · 점선 = 장치 유형에 따른 논리 추정. 일반 서버/네트워크 장치는 임의로 스위치 하위에 배치하지 않습니다.",
            10.5, FontWeights.Normal, muted, new Point(14, 32));
        var coverageBrush = new SolidColorBrush(_captureCoverageSnapshot.IsSpanVerified
            ? (LightTheme ? Color.FromRgb(25, 118, 82) : Color.FromRgb(98, 217, 166))
            : _captureCoverageSnapshot.Mode == PacketCaptureScopeMode.SpanTap
                ? (LightTheme ? Color.FromRgb(145, 116, 0) : Color.FromRgb(250, 216, 59))
                : (LightTheme ? Color.FromRgb(100, 100, 100) : Color.FromRgb(138, 138, 138)));
        DrawText(dc, $"SENSOR  {_captureCoverageSnapshot.ModeText} · {_captureCoverageSnapshot.CoverageStateText}",
            9.4, FontWeights.SemiBold, coverageBrush, new Point(14, 49));
        if (_topologySignificanceSnapshot.ObservedNodeCount > 0)
        {
            string flowView = _includeLowSignificanceExternal
                ? $"FLOW VIEW  전체 외부 {_topologySignificanceSnapshot.RenderedNodeCount:N0}"
                : $"FLOW VIEW  {_topologySignificanceSnapshot.SummaryText}";
            if (_excludeSensorHostConnections)
                flowView += " · 실행 PC 연결 제외";
            var flowViewText = CreateText(flowView, 9.2, FontWeights.SemiBold,
                new SolidColorBrush(LightTheme ? Color.FromRgb(92, 78, 132) : Color.FromRgb(190, 173, 227)));
            dc.DrawText(flowViewText, new Point(Math.Max(14, w - flowViewText.Width - 16), 49));
        }
        if (_trafficSnapshot.TotalCapturedPackets > 0)
        {
            var liveBrush = new SolidColorBrush(LightTheme ? Color.FromRgb(25, 118, 82) : Color.FromRgb(98, 217, 166));
            string live = $"LIVE TRAFFIC  {_trafficSnapshot.CurrentRateText}  ·  {_trafficSnapshot.CurrentPacketsPerSecond:0} pkt/s";
            var liveText = CreateText(live, 10.2, FontWeights.SemiBold, liveBrush);
            dc.DrawText(liveText, new Point(Math.Max(14, w - liveText.Width - 16), 12));
        }
        if (_securityRelationshipSnapshot.HasData)
        {
            Color riskColor = _securityRelationshipSnapshot.HighCount > 0
                ? (LightTheme ? Color.FromRgb(185, 28, 28) : Color.FromRgb(255, 112, 96))
                : _securityRelationshipSnapshot.MediumCount > 0
                    ? (LightTheme ? Color.FromRgb(180, 83, 9) : Color.FromRgb(244, 183, 72))
                    : _securityRelationshipSnapshot.WatchCount > 0
                        ? (LightTheme ? Color.FromRgb(145, 116, 0) : Color.FromRgb(250, 216, 59))
                        : (LightTheme ? Color.FromRgb(25, 118, 82) : Color.FromRgb(98, 217, 166));
            string security = $"SECURITY  H:{_securityRelationshipSnapshot.HighCount}  M:{_securityRelationshipSnapshot.MediumCount}  W:{_securityRelationshipSnapshot.WatchCount}";
            var securityText = CreateText(security, 9.8, FontWeights.SemiBold, new SolidColorBrush(riskColor));
            dc.DrawText(securityText, new Point(Math.Max(14, w - securityText.Width - 16), 31));
        }

        if (_results.Count == 0 && string.IsNullOrWhiteSpace(_gatewayAddress))
        {
            DrawText(dc, "ONLINE 장비가 발견되면 관계도가 자동으로 구성됩니다.", 14, FontWeights.Normal, muted,
                new Point(24, Math.Max(72, h / 2 - 10)));
            return;
        }

        var gatewayResult = _results.FirstOrDefault(r => r.IsGateway) ??
                            _results.FirstOrDefault(r =>
                                (r.DeviceType == DeviceType.Router || r.DeviceType == DeviceType.Firewall) &&
                                !string.IsNullOrWhiteSpace(_gatewayAddress) &&
                                string.Equals(r.IpAddress, _gatewayAddress, StringComparison.OrdinalIgnoreCase));

        string gatewayIp = gatewayResult?.IpAddress ?? _gatewayAddress;
        DeviceType gatewayType = gatewayResult?.DeviceType ?? DeviceType.Router;
        string gatewayHost = gatewayResult?.HostName ?? "";

        var external = GetExternalDisplayResults();
        var rootGateways = _topologyRoots
            .Select(r => r.GatewayAddress)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(gatewayIp)) rootGateways.Add(gatewayIp);

        var local = _results
            .Where(r => !IsPublicIpv4(r.IpAddress) && !rootGateways.Contains(r.IpAddress))
            .OrderBy(r => r.AuditGroupLabel, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(r => r.IpSortKey)
            .ToList();

        double centerX = w / 2;
        double y = 72;

        Point? internetPoint = null;
        if (external.Count > 0)
        {
            internetPoint = P(new Point(centerX, y + 28), w);
            DrawNode(dc, internetPoint.Value, DeviceType.Internet, "Internet", "외부 / 공인 대상", 23, accent, text, true, 0, isSynthetic: true);
            y += 88;
        }

        var gatewayPoint = P(new Point(centerX, y + 28), w);
        if (internetPoint.HasValue)
            DrawNodeEdgeConnection(dc, trunkLine, internetPoint.Value, 23, gatewayPoint, 24, shadow: PerspectiveMode);
        DrawNode(dc, gatewayPoint, gatewayType, gatewayIp, gatewayHost, 24, accent, text, true);
        if (gatewayResult is not null) RegisterHit(gatewayPoint, 24, gatewayResult);
        y += 98;

        if (external.Count > 0)
        {
            double panelHeight = DrawExternalPanel(dc, external, new Rect(42, y, w - 84, CalculatePanelHeight(external.Count, w, 128)),
                panelFill, border, endpointLine, branchLine, accent, text, muted, subtle);
            y += panelHeight + 24;
        }

        var groups = local
            .GroupBy(r => new
            {
                Label = string.IsNullOrWhiteSpace(r.AuditGroupLabel) ? "감사 대역" : r.AuditGroupLabel,
                Expression = r.AuditGroupExpression ?? ""
            })
            .ToList();

        foreach (var group in groups)
        {
            var items = group.ToList();
            var directRoot = _topologyRoots.FirstOrDefault(r =>
                r.IsDirect && (string.Equals(r.GroupLabel, group.Key.Label, StringComparison.OrdinalIgnoreCase) ||
                               (!string.IsNullOrWhiteSpace(group.Key.Expression) && string.Equals(r.Expression, group.Key.Expression, StringComparison.OrdinalIgnoreCase))));
            var nestedRelation = directRoot is not null ? null : FindNestedRelation(items);
            double panelHeight = CalculateGroupPanelHeight(items, w);
            var panelRect = new Rect(42, y, w - 84, panelHeight);
            DrawGroupPanel(dc, group.Key.Label, group.Key.Expression, items, panelRect, gatewayPoint, nestedRelation,
                panelFill, panelAlt, border, endpointLine, inferredLine, branchLine, trunkLine, accent, text, muted, subtle);
            y += panelHeight + 24;
        }

        DrawNestedRelationshipOverlay(dc, groups.Select(g => (g.Key.Label, g.Key.Expression, Items: (IReadOnlyList<ScanResult>)g.ToList())).ToList(), gatewayPoint, inferredLine, muted);
        DrawTrafficOverlay(dc);

        if (PerspectiveMode)
        {
            DrawText(dc, "3D 시점은 시각적 깊이 표현입니다. 실제 물리 배선 또는 포트 연결을 의미하지 않습니다.",
                9.6, FontWeights.Normal, subtle, new Point(14, h - 24));
        }
    }

    private NestedNetworkInfo? FindNestedRelation(IReadOnlyList<ScanResult> items)
    {
        if (items.Count == 0 || _nestedNetworks.Count == 0) return null;
        var ownIps = items.Select(r => r.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var matches = _nestedNetworks
            .Where(n => !ownIps.Contains(n.ParentIp) && items.All(r => n.Contains(r.IpAddress)))
            .OrderByDescending(n => ParsePrefix(n.Cidr))
            .ToList();
        if (matches.Count == 0) return null;
        int bestPrefix = ParsePrefix(matches[0].Cidr);
        var best = matches.Where(n => ParsePrefix(n.Cidr) == bestPrefix).ToList();
        return best.Select(n => n.ParentIp).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1 ? best[0] : null;
    }

    private void DrawNestedRelationshipOverlay(
        DrawingContext dc,
        IReadOnlyList<(string Label, string Expression, IReadOnlyList<ScanResult> Items)> groups,
        Point gatewayPoint,
        Pen inferredLine,
        Brush muted)
    {
        foreach (var group in groups)
        {
            // A directly attached range is already rooted at its own gateway.
            // Do not also draw an inferred SNMP child path for the same range.
            bool isDirectRoot = _topologyRoots.Any(r =>
                r.IsDirect &&
                (string.Equals(r.GroupLabel, group.Label, StringComparison.OrdinalIgnoreCase) ||
                 (!string.IsNullOrWhiteSpace(group.Expression) &&
                  string.Equals(r.Expression, group.Expression, StringComparison.OrdinalIgnoreCase))));
            if (isDirectRoot) continue;

            var relation = FindNestedRelation(group.Items);
            if (relation is null) continue;
            if (!_groupAnchors.TryGetValue(GroupAnchorKey(group.Label, group.Expression), out var childAnchor)) continue;

            if (_nodeCenters.TryGetValue(relation.ParentIp, out var parentPoint))
            {
                DrawNestedElbowConnection(dc, inferredLine, parentPoint, childAnchor, shadow: PerspectiveMode);
                DrawText(dc, "SNMP child", 8.6, FontWeights.SemiBold, muted,
                    new Point(childAnchor.X + 26, childAnchor.Y - 18));
            }
            else
            {
                // Keep an unresolved child group visible without claiming a direct physical path.
                // Route through the left gutter so the inferred link does not cut diagonally through device rows.
                DrawNestedElbowConnection(dc, inferredLine, gatewayPoint, childAnchor, shadow: PerspectiveMode);
                DrawText(dc, "parent unresolved", 8.2, FontWeights.Normal, muted,
                    new Point(childAnchor.X + 24, childAnchor.Y - 18));
            }
        }
    }

    private static string GroupAnchorKey(string label, string expression) => $"{label}\n{expression}";

    private static int ParsePrefix(string cidr)
    {
        var parts = cidr.Split('/');
        return parts.Length == 2 && int.TryParse(parts[1], out int prefix) ? prefix : 0;
    }

    private double DrawExternalPanel(
        DrawingContext dc,
        IReadOnlyList<ScanResult> external,
        Rect panelRect,
        Brush panelFill,
        Pen border,
        Pen endpointLine,
        Pen branchLine,
        Brush accent,
        Brush text,
        Brush muted,
        Brush subtle)
    {
        DrawPanel(dc, panelRect, panelFill, border);
        string externalTitle = _captureCoverageSnapshot.CanRenderObservedExternalTopology && _topologySignificanceSnapshot.ObservedNodeCount > 0
            ? $"외부 / 공인 대상  ·  표시 {external.Count:N0}개 · 관측 {_topologySignificanceSnapshot.ObservedNodeCount:N0} · 숨김 {_topologySignificanceSnapshot.SuppressedNodeCount:N0}" +
              (_excludeSensorHostConnections ? $" · 실행 PC Flow 제외 {_topologySignificanceSnapshot.SensorHostSuppressedFlowCount:N0}" : string.Empty)
            : $"외부 / 공인 대상  ·  {external.Count:N0}개";
        DrawText(dc, externalTitle, 12.5, FontWeights.SemiBold, text,
            P(new Point(panelRect.Left + 18, panelRect.Top + 14), ActualWidth));
        string externalDescription = _captureCoverageSnapshot.CanRenderObservedExternalTopology
            ? _includeLowSignificanceExternal
                ? "전체 외부 관측 표시 모드입니다. 패킷/Flow는 모두 분석에 유지되며 화면에도 저중요 노드까지 표시합니다."
                : $"Significant Flow Rendering · 장비별 공정 Top-N + 보안 위험 강제 표시로 화면 노이즈를 억제합니다.{(string.IsNullOrWhiteSpace(_topologySignificanceSnapshot.ServiceSummaryText) ? "" : $"  주요 그룹: {_topologySignificanceSnapshot.ServiceSummaryText}")}"
            : "현재 센서 관측 범위에서는 수동 관찰 External/Public 노드를 숨깁니다. 이 영역에는 명시적으로 스캔한 공인 IP만 표시됩니다.";
        DrawText(dc, externalDescription,
            9.5, FontWeights.Normal, muted, P(new Point(panelRect.Left + 18, panelRect.Top + 35), ActualWidth));

        var anchor = P(new Point(panelRect.Left + 64, panelRect.Top + 82), ActualWidth);
        DrawNode(dc, anchor, DeviceType.Internet, "PUBLIC", "외부망", 18, accent, text, false, external.Count, isSynthetic: true);

        DrawGridBus(dc, external, panelRect, 118, anchor, endpointLine, branchLine, text, muted, parentAware: false);
        return panelRect.Height;
    }

    private void DrawGroupPanel(
        DrawingContext dc,
        string groupLabel,
        string expression,
        IReadOnlyList<ScanResult> items,
        Rect panelRect,
        Point gatewayPoint,
        NestedNetworkInfo? nestedRelation,
        Brush panelFill,
        Brush panelAlt,
        Pen border,
        Pen endpointLine,
        Pen inferredLine,
        Pen branchLine,
        Pen trunkLine,
        Brush accent,
        Brush text,
        Brush muted,
        Brush subtle)
    {
        DrawPanel(dc, panelRect, panelFill, border);

        DrawText(dc, $"{groupLabel}  ·  {items.Count:N0} devices", 12.5, FontWeights.SemiBold, text,
            P(new Point(panelRect.Left + 18, panelRect.Top + 14), ActualWidth));
        if (!string.IsNullOrWhiteSpace(expression))
            DrawText(dc, expression, 9.5, FontWeights.Normal, muted,
                P(new Point(panelRect.Left + 18, panelRect.Top + 35), ActualWidth));

        if (nestedRelation is not null)
        {
            DrawText(dc, $"↳ 하위망 · {nestedRelation.ParentIp} → {nestedRelation.Cidr} · {nestedRelation.ReachabilityText}",
                9.0, FontWeights.SemiBold, nestedRelation.IsRouteConfirmed ? new SolidColorBrush(Color.FromRgb(88, 190, 155)) : accent,
                P(new Point(panelRect.Left + 18, panelRect.Top + 52), ActualWidth));
        }

        var anchorRaw = new Point(panelRect.Left + 64, panelRect.Top + 83);
        var anchor = P(anchorRaw, ActualWidth);
        var topologyRoot = _topologyRoots.FirstOrDefault(r =>
            string.Equals(r.GroupLabel, groupLabel, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrWhiteSpace(expression) && string.Equals(r.Expression, expression, StringComparison.OrdinalIgnoreCase)));
        bool independentRoot = nestedRelation is null && topologyRoot is { IsDirect: true } &&
                               !string.IsNullOrWhiteSpace(topologyRoot.GatewayAddress) &&
                               !string.Equals(topologyRoot.GatewayAddress, _gatewayAddress, StringComparison.OrdinalIgnoreCase);
        if (nestedRelation is null && !independentRoot)
            DrawGatewayBackboneConnection(dc, trunkLine, gatewayPoint, anchorRaw, panelRect, shadow: PerspectiveMode);
        _groupAnchors[GroupAnchorKey(groupLabel, expression)] = anchor;
        if (independentRoot)
        {
            DrawNode(dc, anchor, DeviceType.Router, $"GW {topologyRoot!.GatewayAddress}", $"{groupLabel} · {expression}", 20, accent, text, true, items.Count, isSynthetic: true);
            DrawText(dc, "독립 직접 연결 대역", 8.7, FontWeights.SemiBold, accent, new Point(anchor.X + 28, anchor.Y - 10));
        }
        else
        {
            DrawNode(dc, anchor, DeviceType.NetworkDevice, groupLabel, expression, 18, accent, text, false, items.Count, isSynthetic: true);
        }

        // Only strongly identified infrastructure devices are promoted into the infrastructure lane.
        // Generic NetworkDevice and Server remain leaf endpoints; this prevents SSH/HTTP servers from
        // becoming false switch/hub parents.
        var infrastructure = items
            .Where(r => IsStrongInfrastructure(r.DeviceType))
            .OrderBy(r => InfrastructureOrder(r.DeviceType))
            .ThenBy(r => r.IpSortKey)
            .ToList();

        // Servers, NAS, hypervisors and printers are important audit assets, but they are not topology
        // parents. Render them on a separate long branch so they stand out without inventing children.
        var specialAssets = items
            .Where(r => !infrastructure.Contains(r) && IsSpecialAsset(r.DeviceType))
            .OrderBy(r => SpecialAssetOrder(r.DeviceType))
            .ThenBy(r => r.IpSortKey)
            .ToList();

        var endpoints = items
            .Where(r => !infrastructure.Contains(r) && !specialAssets.Contains(r))
            .ToList();

        double infraY = panelRect.Top + 92;
        if (infrastructure.Count > 0)
        {
            double startX = panelRect.Left + 150;
            double endX = panelRect.Right - 34;
            int columns = Math.Max(1, (int)Math.Floor((endX - startX) / 132.0));
            int rows = (int)Math.Ceiling(infrastructure.Count / (double)columns);

            for (int row = 0; row < rows; row++)
            {
                var rowItems = infrastructure.Skip(row * columns).Take(columns).ToList();
                double rowY = infraY + row * 76;
                var busStart = P(new Point(startX - 20, rowY), ActualWidth);
                var busEnd = P(new Point(endX, rowY), ActualWidth);
                DrawAnchorBusConnection(dc, branchLine, anchor, busStart, shadow: PerspectiveMode);
                DrawConnection(dc, branchLine, busStart, busEnd, shadow: PerspectiveMode);

                for (int i = 0; i < rowItems.Count; i++)
                {
                    double x = startX + (i + 0.5) * (endX - startX) / Math.Max(1, rowItems.Count);
                    var nodePos = P(new Point(x, rowY + 25), ActualWidth);
                    var branchTop = P(new Point(x, rowY), ActualWidth);
                    DrawConnection(dc, branchLine, branchTop, nodePos, shadow: PerspectiveMode);
                    DrawNode(dc, nodePos, rowItems[i].DeviceType, rowItems[i].IpAddress, rowItems[i].HostName,
                        18.5, accent, text, false, 0);
                    RegisterHit(nodePos, 18.5, rowItems[i]);
                    DrawNestedNetworkIndicator(dc, rowItems[i], nodePos, muted, text);
                }
            }
        }

        int infraRows = InfrastructureRows(infrastructure.Count, panelRect.Width);
        double specialTop = panelRect.Top + 150 + infraRows * 76;
        int specialRows = SpecialAssetRows(specialAssets.Count, panelRect.Width);

        if (specialAssets.Count > 0)
        {
            DrawText(dc, $"특수 자산  ·  서버 / NAS / 가상화 / 프린터  ·  {specialAssets.Count:N0}개",
                9.6, FontWeights.SemiBold, accent,
                P(new Point(panelRect.Left + 150, specialTop - 8), ActualWidth));

            double startX = panelRect.Left + 190;
            double endX = panelRect.Right - 34;
            const double cellW = 138;
            const double rowH = 86;
            int columns = Math.Max(1, (int)Math.Floor((endX - startX) / cellW));

            for (int row = 0; row < specialRows; row++)
            {
                var rowItems = specialAssets.Skip(row * columns).Take(columns).ToList();
                double busY = specialTop + 23 + row * rowH;
                var stemStart = P(new Point(panelRect.Left + 122, busY), ActualWidth);
                var busStart = P(new Point(startX - 22, busY), ActualWidth);
                var busEnd = P(new Point(Math.Min(endX, startX + Math.Max(cellW, rowItems.Count * cellW)), busY), ActualWidth);

                DrawAnchorBusConnection(dc, branchLine, anchor, stemStart, shadow: PerspectiveMode);
                DrawConnection(dc, branchLine, stemStart, busStart, shadow: PerspectiveMode);
                DrawConnection(dc, branchLine, busStart, busEnd, shadow: PerspectiveMode);

                for (int i = 0; i < rowItems.Count; i++)
                {
                    var item = rowItems[i];
                    double x = startX + (i + 0.5) * cellW;
                    if (x > endX) x = endX;
                    var nodePos = P(new Point(x, busY + 28), ActualWidth);
                    var branchTop = P(new Point(x, busY), ActualWidth);
                    DrawConnection(dc, branchLine, branchTop, nodePos, shadow: PerspectiveMode);
                    string specialHost = string.IsNullOrWhiteSpace(item.HostName)
                        ? item.DeviceLabel
                        : $"{item.DeviceLabel} · {item.HostName}";
                    DrawNode(dc, nodePos, item.DeviceType, item.IpAddress, specialHost, 17.5,
                        SpecialAssetBrush(item.DeviceType), text, false, 0);
                    RegisterHit(nodePos, 17.5, item);
                }
            }
        }

        double endpointTop = specialAssets.Count > 0
            ? specialTop + 54 + specialRows * 86
            : panelRect.Top + 156 + infraRows * 76;

        DrawGridBus(dc, endpoints,
            new Rect(panelRect.Left, endpointTop - 38, panelRect.Width, Math.Max(80, panelRect.Bottom - endpointTop + 38)),
            76, anchor, endpointLine, inferredLine, text, muted, parentAware: true, infrastructure: infrastructure);

        if (infrastructure.Count == 0)
        {
            DrawText(dc, "확정 가능한 스위치/AP/라우터가 없어 장비를 감사 대역 기준으로만 연결했습니다.",
                9.4, FontWeights.Normal, subtle, P(new Point(panelRect.Left + 150, panelRect.Top + 62), ActualWidth));
        }
    }

    private void DrawGridBus(
        DrawingContext dc,
        IReadOnlyList<ScanResult> devices,
        Rect area,
        double firstRowOffset,
        Point anchor,
        Pen endpointLine,
        Pen branchLine,
        Brush text,
        Brush muted,
        bool parentAware,
        IReadOnlyList<ScanResult>? infrastructure = null)
    {
        if (devices.Count == 0) return;

        double startX = area.Left + 150;
        double endX = area.Right - 34;
        const double cellW = 116;
        const double rowH = 78;
        int columns = Math.Max(1, (int)Math.Floor((endX - startX) / cellW));

        int rows = (int)Math.Ceiling(devices.Count / (double)columns);
        for (int row = 0; row < rows; row++)
        {
            var rowItems = devices.Skip(row * columns).Take(columns).ToList();
            double rowY = area.Top + firstRowOffset + row * rowH;
            double rowWidth = Math.Min(endX - startX, Math.Max(cellW, rowItems.Count * cellW));
            double busEndX = Math.Min(endX, startX + rowWidth);
            var busStart = P(new Point(startX - 20, rowY), ActualWidth);
            var busEnd = P(new Point(busEndX, rowY), ActualWidth);
            DrawAnchorBusConnection(dc, endpointLine, anchor, busStart, shadow: PerspectiveMode);
            DrawConnection(dc, endpointLine, busStart, busEnd, shadow: PerspectiveMode);

            for (int i = 0; i < rowItems.Count; i++)
            {
                var item = rowItems[i];
                double x = startX + (i + 0.5) * cellW;
                if (x > endX) x = endX;
                var nodePos = P(new Point(x, rowY + 25), ActualWidth);
                var branchTop = P(new Point(x, rowY), ActualWidth);
                DrawConnection(dc, endpointLine, branchTop, nodePos, shadow: PerspectiveMode);
                DrawNode(dc, nodePos, item.DeviceType, item.IpAddress, item.HostName, 15.5, muted, text, false, 0);
                RegisterHit(nodePos, 15.5, item);
            }
        }
    }

    private static int InfrastructureRows(int count, double panelWidth)
    {
        if (count <= 0) return 0;
        double usable = Math.Max(132, panelWidth - 210);
        int columns = Math.Max(1, (int)Math.Floor(usable / 132.0));
        return (int)Math.Ceiling(count / (double)columns);
    }

    private static int SpecialAssetRows(int count, double panelWidth)
    {
        if (count <= 0) return 0;
        double usable = Math.Max(138, panelWidth - 250);
        int columns = Math.Max(1, (int)Math.Floor(usable / 138.0));
        return (int)Math.Ceiling(count / (double)columns);
    }

    private static double CalculateGroupPanelHeight(IReadOnlyList<ScanResult> items, double canvasWidth)
    {
        int infraCount = items.Count(r => IsStrongInfrastructure(r.DeviceType));
        int specialCount = items.Count(r => !IsStrongInfrastructure(r.DeviceType) && IsSpecialAsset(r.DeviceType));
        int endpointCount = Math.Max(0, items.Count - infraCount - specialCount);
        double panelWidth = canvasWidth - 84;
        double usable = Math.Max(116, panelWidth - 184);
        int columns = Math.Max(1, (int)Math.Floor(usable / 116.0));
        int endpointRows = Math.Max(1, (int)Math.Ceiling(endpointCount / (double)columns));
        int infraRows = InfrastructureRows(infraCount, panelWidth);
        int specialRows = SpecialAssetRows(specialCount, panelWidth);
        double specialHeight = specialCount > 0 ? 58 + specialRows * 86 : 0;
        return 196 + infraRows * 76 + specialHeight + endpointRows * 78;
    }

    private static double CalculatePanelHeight(int count, double canvasWidth, double topReserve)
    {
        double usable = Math.Max(116, canvasWidth - 268);
        int columns = Math.Max(1, (int)Math.Floor(usable / 116.0));
        int rows = Math.Max(1, (int)Math.Ceiling(count / (double)columns));
        return topReserve + rows * 78 + 34;
    }

    private void RegisterHit(Point center, double radius, ScanResult result)
    {
        double r = Math.Max(radius + 9, 24);
        _hitRegions.Add((new Rect(center.X - r, center.Y - r, r * 2, r * 2 + 20), result));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var point = e.GetPosition(this);
        Cursor = _hitRegions.Any(hit => hit.Bounds.Contains(point)) ? Cursors.Hand : Cursors.Arrow;
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonUp(e);
        var point = e.GetPosition(this);
        for (int i = _hitRegions.Count - 1; i >= 0; i--)
        {
            if (!_hitRegions[i].Bounds.Contains(point)) continue;
            DeviceNodeClicked?.Invoke(_hitRegions[i].Result);
            e.Handled = true;
            break;
        }
    }

    private void DrawPanel(DrawingContext dc, Rect rect, Brush fill, Pen border)
    {
        if (!PerspectiveMode)
        {
            dc.DrawRoundedRectangle(fill, border, rect, 7, 7);
            return;
        }

        var shadow = new SolidColorBrush(LightTheme ? Color.FromArgb(24, 0, 0, 0) : Color.FromArgb(70, 0, 0, 0));
        dc.DrawRoundedRectangle(shadow, null, new Rect(rect.X + 8, rect.Y + 8, rect.Width, rect.Height), 8, 8);
        dc.DrawRoundedRectangle(fill, border, rect, 7, 7);
        dc.DrawLine(new Pen(BrushRgb(LightTheme ? (220, 220, 220) : (48, 48, 48)), 1),
            new Point(rect.Left + 12, rect.Top + 54), new Point(rect.Right - 12, rect.Top + 54));
    }

    private void DrawConnection(DrawingContext dc, Pen pen, Point a, Point b, bool shadow)
    {
        DrawPolylineConnection(dc, pen, new[] { a, b }, shadow);
    }

    private void DrawNodeEdgeConnection(DrawingContext dc, Pen pen, Point upperCenter, double upperRadius, Point lowerCenter, double lowerRadius, bool shadow)
    {
        var start = new Point(upperCenter.X, upperCenter.Y + upperRadius + 2);
        var end = new Point(lowerCenter.X, lowerCenter.Y - lowerRadius - 2);
        DrawConnection(dc, pen, start, end, shadow);
    }

    private void DrawGatewayBackboneConnection(
        DrawingContext dc,
        Pen pen,
        Point gatewayPoint,
        Point anchorRaw,
        Rect panelRect,
        bool shadow)
    {
        // Structural range links are intentionally routed through the left gutter.
        // A direct diagonal from the centered gateway to a subnet anchor used to cut across
        // headings and device lanes and looked like an arbitrary point-to-point relationship.
        double gutterRawX = Math.Max(16, panelRect.Left - 18);
        // Exit the main gateway from the left side instead of the bottom edge.
        // The old bottom attachment visually collided with the router label/icon and looked like
        // a dangling cable rather than the start of the structural backbone.
        double gatewayExitY = gatewayPoint.Y + 1;
        var gatewayExit = new Point(gatewayPoint.X - 28, gatewayExitY);
        var gutterTop = P(new Point(gutterRawX, gatewayExitY), ActualWidth);
        var gutterAtAnchor = P(new Point(gutterRawX, anchorRaw.Y), ActualWidth);
        var anchor = P(anchorRaw, ActualWidth);
        var anchorEntry = new Point(anchor.X - 21, anchor.Y);

        DrawPolylineConnection(dc, pen, new[] { gatewayExit, gutterTop, gutterAtAnchor, anchorEntry }, shadow);
        DrawConnection(dc, pen, anchorEntry, new Point(anchor.X - 18, anchor.Y), shadow: false);
    }

    private void DrawAnchorBusConnection(DrawingContext dc, Pen pen, Point anchor, Point busStart, bool shadow)
    {
        // Use a vertical local backbone and a short horizontal branch for each device row.
        // This removes the old fan of diagonal lines radiating from the subnet anchor.
        var elbow = new Point(anchor.X, busStart.Y);
        DrawPolylineConnection(dc, pen, new[] { anchor, elbow, busStart }, shadow);
    }

    private void DrawNestedElbowConnection(DrawingContext dc, Pen pen, Point parent, Point child, bool shadow)
    {
        // Keep inferred parent/child relationships visually separate from the main device rows.
        // The left gutter acts as a topology backbone, while the dashed style continues to
        // communicate that the relation was inferred from SNMP/routing evidence.
        double gutterRawX = 24;
        double parentExitY = parent.Y + 28;
        var parentExit = new Point(parent.X, parentExitY);
        var gutterTop = P(new Point(gutterRawX, parentExitY), ActualWidth);
        var gutterBottom = P(new Point(gutterRawX, child.Y), ActualWidth);
        var childEntry = new Point(child.X - 21, child.Y);
        DrawPolylineConnection(dc, pen, new[] { parentExit, gutterTop, gutterBottom, childEntry }, shadow);
    }

    private void DrawPolylineConnection(DrawingContext dc, Pen pen, IReadOnlyList<Point> points, bool shadow)
    {
        if (points.Count < 2) return;

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(points[0], isFilled: false, isClosed: false);
            ctx.PolyLineTo(points.Skip(1).ToArray(), isStroked: true, isSmoothJoin: true);
        }
        geometry.Freeze();

        if (shadow)
        {
            var shadowPen = new Pen(new SolidColorBrush(Color.FromArgb(LightTheme ? (byte)24 : (byte)80, 0, 0, 0)), pen.Thickness + 1.4)
            {
                DashStyle = pen.DashStyle,
                LineJoin = PenLineJoin.Round
            };
            var translated = geometry.Clone();
            translated.Transform = new TranslateTransform(3, 3);
            dc.DrawGeometry(null, shadowPen, translated);
        }

        pen.LineJoin = PenLineJoin.Round;
        dc.DrawGeometry(null, pen, geometry);
    }

    private Point P(Point raw, double width)
    {
        if (!PerspectiveMode) return raw;

        double centerX = width / 2;
        double depth = Math.Clamp((raw.Y - 55) / Math.Max(1, ActualHeight - 80), 0, 1);
        double scale = 0.90 + depth * 0.10;
        double x = centerX + (raw.X - centerX) * scale + depth * 16;
        double y = raw.Y;
        return new Point(x, y);
    }

    private void DrawNode(
        DrawingContext dc,
        Point center,
        DeviceType deviceType,
        string ip,
        string hostName,
        double radius,
        Brush edgeBrush,
        Brush textBrush,
        bool isCenter,
        int childCount = 0,
        bool isSynthetic = false)
    {
        bool dimmed = !isSynthetic && IsDimmed(deviceType);
        if (dimmed) dc.PushOpacity(0.18);

        if (PerspectiveMode)
        {
            var shadowFill = new SolidColorBrush(Color.FromArgb(LightTheme ? (byte)28 : (byte)92, 0, 0, 0));
            dc.DrawEllipse(shadowFill, null, new Point(center.X + 4, center.Y + 4), radius, radius);
        }

        var nodeFill = new SolidColorBrush(LightTheme ? Color.FromRgb(250, 250, 250) : Color.FromRgb(29, 29, 29));
        var edge = new Pen(edgeBrush, isCenter ? 2.1 : 1.25);
        dc.DrawEllipse(nodeFill, edge, center, radius, radius);

        double iconSize = radius * 1.25;
        DeviceDrawingHelper.Draw(dc, deviceType,
            new Rect(center.X - iconSize / 2, center.Y - iconSize / 2, iconSize, iconSize),
            isCenter || isSynthetic
                ? new SolidColorBrush(LightTheme ? Color.FromRgb(158, 132, 0) : Color.FromRgb(250, 216, 59))
                : new SolidColorBrush(LightTheme ? Color.FromRgb(70, 70, 70) : Color.FromRgb(222, 222, 222)));

        if (childCount > 0 && (isSynthetic || IsStrongInfrastructure(deviceType)))
        {
            var badgeFill = new SolidColorBrush(LightTheme ? Color.FromRgb(245, 238, 196) : Color.FromRgb(54, 49, 27));
            var badgeEdge = new Pen(new SolidColorBrush(LightTheme ? Color.FromRgb(158, 132, 0) : Color.FromRgb(250, 216, 59)), 1);
            var badgeCenter = new Point(center.X + radius * 0.72, center.Y - radius * 0.72);
            dc.DrawEllipse(badgeFill, badgeEdge, badgeCenter, 7.5, 7.5);
            var countText = CreateText(childCount.ToString(CultureInfo.InvariantCulture), 7.7, FontWeights.Bold, textBrush);
            dc.DrawText(countText, new Point(badgeCenter.X - countText.Width / 2, badgeCenter.Y - countText.Height / 2));
        }

        if (!isSynthetic && !string.IsNullOrWhiteSpace(ip))
        {
            _nodeCenters[ip] = center;
            DrawTrafficActivityRing(dc, center, radius, ip);
            DrawSecurityRiskRing(dc, center, radius, ip);
        }

        var label = MakeLabel(ip, hostName, isCenter, isSynthetic);
        var ft = CreateText(label, isCenter ? 10.5 : 9.2, isCenter ? FontWeights.SemiBold : FontWeights.Normal, textBrush);
        dc.DrawText(ft, new Point(center.X - ft.Width / 2, center.Y + radius + 4));
        if (dimmed) dc.Pop();
    }

    private void DrawNestedNetworkIndicator(DrawingContext dc, ScanResult parent, Point center, Brush muted, Brush text)
    {
        var nested = _nestedNetworks.Where(n => string.Equals(n.ParentIp, parent.IpAddress, StringComparison.OrdinalIgnoreCase)).ToList();
        if (nested.Count == 0) return;

        string first = nested[0].Cidr;
        string suffix = nested.Count > 1 ? $"  +{nested.Count - 1}" : "";
        string label = $"↳ {first}{suffix}";
        var ft = CreateText(label, 8.6, FontWeights.SemiBold,
            new SolidColorBrush(nested.Any(n => n.IsRouteConfirmed)
                ? (LightTheme ? Color.FromRgb(45, 122, 88) : Color.FromRgb(98, 217, 166))
                : (LightTheme ? Color.FromRgb(145, 116, 0) : Color.FromRgb(222, 192, 72))));
        double x = center.X - ft.Width / 2;
        double y = center.Y + 39;
        var bg = new SolidColorBrush(LightTheme ? Color.FromRgb(248, 248, 248) : Color.FromRgb(25, 25, 25));
        var pen = new Pen(new SolidColorBrush(LightTheme ? Color.FromRgb(210, 210, 210) : Color.FromRgb(64, 64, 64)), 1);
        var rect = new Rect(x - 5, y - 2, ft.Width + 10, ft.Height + 4);
        dc.DrawRoundedRectangle(bg, pen, rect, 4, 4);
        dc.DrawText(ft, new Point(x, y));
    }

    private void DrawTrafficActivityRing(DrawingContext dc, Point center, double radius, string ip)
    {
        if (!_trafficSnapshot.Nodes.TryGetValue(ip, out var stat) || !stat.IsActive) return;
        double rate = Math.Max(stat.TotalBytesPerSecond, stat.TotalPacketsPerSecond * 80.0);
        double intensity = Math.Clamp(Math.Log10(1.0 + rate) / 5.0, 0.18, 1.0);
        byte alpha = (byte)Math.Clamp(70 + intensity * 150, 70, 220);
        var brush = new SolidColorBrush(Color.FromArgb(alpha, 98, 217, 166));
        var pen = new Pen(brush, 1.4 + intensity * 2.6);
        dc.DrawEllipse(null, pen, center, radius + 5 + intensity * 3, radius + 5 + intensity * 3);
    }

    private void DrawSecurityRiskRing(DrawingContext dc, Point center, double radius, string ip)
    {
        var assessment = _securityRelationshipSnapshot.FindNode(ip);
        if (assessment is null || assessment.RiskScore < 25) return;

        Color color = assessment.RiskLevel switch
        {
            "HIGH" => LightTheme ? Color.FromRgb(185, 28, 28) : Color.FromRgb(255, 94, 77),
            "MEDIUM" => LightTheme ? Color.FromRgb(180, 83, 9) : Color.FromRgb(244, 183, 72),
            _ => LightTheme ? Color.FromRgb(145, 116, 0) : Color.FromRgb(250, 216, 59)
        };
        double strength = Math.Clamp(assessment.RiskScore / 100.0, 0.25, 1.0);
        var brush = new SolidColorBrush(Color.FromArgb((byte)(120 + strength * 110), color.R, color.G, color.B));
        var pen = new Pen(brush, 1.6 + strength * 2.2) { DashStyle = assessment.RiskLevel == "HIGH" ? DashStyles.Solid : DashStyles.Dash };
        double rr = radius + 10 + strength * 3;
        dc.DrawEllipse(null, pen, center, rr, rr);

        string badge = assessment.ExternalIntelSuspiciousCount > 0
            ? $"INTEL {assessment.RiskScore}"
            : assessment.DnsAnomalyScore >= 30
                ? $"DNS {assessment.RiskScore}"
                : assessment.BeaconCandidateCount > 0
                    ? $"BEACON {assessment.RiskScore}"
                    : assessment.LateralMovementTargetCount >= 4 && !assessment.PolicyTrustedInternal
                        ? $"LATERAL {assessment.RiskScore}"
                        : assessment.BaselineReady && assessment.BaselineAnomalyScore >= 30
                            ? $"BASELINE {assessment.RiskScore}"
                            : $"RISK {assessment.RiskScore}";
        var ft = CreateText(badge, 7.6, FontWeights.Bold, brush);
        var rect = new Rect(center.X - ft.Width / 2 - 4, center.Y - rr - ft.Height - 4, ft.Width + 8, ft.Height + 3);
        dc.DrawRoundedRectangle(new SolidColorBrush(LightTheme ? Color.FromArgb(235, 255, 255, 255) : Color.FromArgb(220, 24, 24, 24)), new Pen(brush, 0.8), rect, 3, 3);
        dc.DrawText(ft, new Point(rect.X + 4, rect.Y + 1));
    }

    private void DrawTrafficOverlay(DrawingContext dc)
    {
        if (_nodeCenters.Count == 0) return;

        // Retained External/Public observation history is deliberately drawn underneath LIVE
        // traffic. It remains after the short live window expires and disappears only when the
        // user clears the external observation history.
        DrawExternalObservationOverlay(dc);
        DrawSecurityRelationshipOverlay(dc);

        if (_trafficSnapshot.Flows.Count == 0) return;
        foreach (var flow in _trafficSnapshot.Flows.Take(24))
        {
            if (IsExcludedSensorHostExternalFlow(flow.SourceIp, flow.DestinationIp)) continue;
            if (!_nodeCenters.TryGetValue(flow.SourceIp, out var a) || !_nodeCenters.TryGetValue(flow.DestinationIp, out var b))
                continue;

            double strength = Math.Clamp(Math.Log10(1.0 + flow.BytesPerSecond) / 5.0, 0.15, 1.0);
            byte alpha = (byte)Math.Clamp(55 + strength * 150, 55, 190);
            var brush = new SolidColorBrush(Color.FromArgb(alpha, 98, 217, 166));
            var pen = new Pen(brush, 1.0 + strength * 2.0)
            {
                DashStyle = new DashStyle(new[] { 5.0, 3.5 }, 0),
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round
            };

            // Live communication is a curved, animated overlay rather than another straight
            // topology edge. This prevents a busy traffic flow from being mistaken for a
            // structural gateway/subnet connection.
            var control = TrafficCurveControlPoint(a, b, flow.SourceIp, flow.DestinationIp);
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(a, isFilled: false, isClosed: false);
                ctx.QuadraticBezierTo(control, b, isStroked: true, isSmoothJoin: true);
            }
            geometry.Freeze();
            dc.DrawGeometry(null, pen, geometry);

            double phase = (DateTime.UtcNow.TimeOfDay.TotalSeconds * (0.35 + strength * 1.3)) % 1.0;
            var pulse = QuadraticPoint(a, control, b, phase);
            dc.DrawEllipse(brush, null, pulse, 2.4 + strength * 1.9, 2.4 + strength * 1.9);

            if (strength >= 0.32)
                DrawTrafficArrow(dc, brush, control, b, 5.0 + strength * 2.0);
        }
    }

    private void DrawSecurityRelationshipOverlay(DrawingContext dc)
    {
        if (_securityRelationshipSnapshot.SuspiciousFlows.Count == 0) return;
        foreach (var flow in _securityRelationshipSnapshot.SuspiciousFlows
                     .OrderByDescending(f => f.RiskScore)
                     .ThenByDescending(f => f.Bytes)
                     .Take(36))
        {
            if (IsExcludedSensorHostExternalFlow(flow.SourceIp, flow.DestinationIp)) continue;
            if (!_nodeCenters.TryGetValue(flow.SourceIp, out var a) || !_nodeCenters.TryGetValue(flow.DestinationIp, out var b))
                continue;

            Color color = flow.RiskLevel switch
            {
                "HIGH" => Color.FromRgb(255, 94, 77),
                "MEDIUM" => Color.FromRgb(244, 183, 72),
                _ => Color.FromRgb(250, 216, 59)
            };
            double strength = Math.Clamp(flow.RiskScore / 100.0, 0.18, 1.0);
            var brush = new SolidColorBrush(Color.FromArgb((byte)Math.Clamp(80 + strength * 145, 80, 220), color.R, color.G, color.B));
            var pen = new Pen(brush, 1.2 + strength * 2.6)
            {
                DashStyle = flow.RiskLevel == "HIGH" ? DashStyles.Solid : new DashStyle(new[] { 4.0, 2.5 }, 0),
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round
            };

            var control = TrafficCurveControlPoint(a, b, flow.SourceIp + "|SEC", flow.DestinationIp);
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(a, isFilled: false, isClosed: false);
                ctx.QuadraticBezierTo(control, b, isStroked: true, isSmoothJoin: true);
            }
            geometry.Freeze();
            dc.DrawGeometry(null, pen, geometry);
            DrawTrafficArrow(dc, brush, control, b, 5.2 + strength * 2.8);
        }
    }

    private void DrawExternalObservationOverlay(DrawingContext dc)
    {
        if (_topologySignificanceSnapshot.ExternalFlows.Count == 0) return;

        foreach (var flow in _topologySignificanceSnapshot.ExternalFlows
                     .OrderByDescending(f => f.Bytes)
                     .ThenByDescending(f => f.Packets)
                     .Take(72))
        {
            if (!_nodeCenters.TryGetValue(flow.SourceIp, out var a) || !_nodeCenters.TryGetValue(flow.DestinationIp, out var b))
                continue;

            double strength = Math.Clamp(Math.Log10(1.0 + flow.Bytes) / 8.0, 0.10, 0.72);
            byte alpha = (byte)Math.Clamp(42 + strength * 92, 42, 118);
            var brush = new SolidColorBrush(Color.FromArgb(alpha, 171, 154, 214));
            var pen = new Pen(brush, 0.8 + strength * 1.4)
            {
                DashStyle = new DashStyle(new[] { 2.5, 5.5 }, 0),
                StartLineCap = PenLineCap.Round,
                EndLineCap = PenLineCap.Round
            };

            var control = TrafficCurveControlPoint(a, b, flow.SourceIp, flow.DestinationIp);
            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(a, isFilled: false, isClosed: false);
                ctx.QuadraticBezierTo(control, b, isStroked: true, isSmoothJoin: true);
            }
            geometry.Freeze();
            dc.DrawGeometry(null, pen, geometry);

            if (strength >= 0.16)
                DrawTrafficArrow(dc, brush, control, b, 4.2 + strength * 1.6);
        }
    }

    private static Point TrafficCurveControlPoint(Point a, Point b, string sourceIp, string destinationIp)
    {
        double dx = b.X - a.X;
        double dy = b.Y - a.Y;
        double length = Math.Max(1.0, Math.Sqrt(dx * dx + dy * dy));
        double nx = -dy / length;
        double ny = dx / length;
        int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(sourceIp + "|" + destinationIp);
        double sign = (hash & 1) == 0 ? 1.0 : -1.0;
        double bend = Math.Clamp(length * 0.10, 18.0, 62.0) * sign;
        return new Point((a.X + b.X) / 2.0 + nx * bend, (a.Y + b.Y) / 2.0 + ny * bend);
    }

    private static Point QuadraticPoint(Point a, Point c, Point b, double t)
    {
        double u = 1.0 - t;
        return new Point(
            u * u * a.X + 2.0 * u * t * c.X + t * t * b.X,
            u * u * a.Y + 2.0 * u * t * c.Y + t * t * b.Y);
    }

    private static void DrawTrafficArrow(DrawingContext dc, Brush brush, Point control, Point destination, double size)
    {
        var vx = destination.X - control.X;
        var vy = destination.Y - control.Y;
        double length = Math.Max(1.0, Math.Sqrt(vx * vx + vy * vy));
        vx /= length;
        vy /= length;
        var nx = -vy;
        var ny = vx;

        var tip = new Point(destination.X - vx * 18, destination.Y - vy * 18);
        var left = new Point(tip.X - vx * size + nx * size * 0.55, tip.Y - vy * size + ny * size * 0.55);
        var right = new Point(tip.X - vx * size - nx * size * 0.55, tip.Y - vy * size - ny * size * 0.55);
        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(tip, isFilled: true, isClosed: true);
            ctx.LineTo(left, isStroked: false, isSmoothJoin: false);
            ctx.LineTo(right, isStroked: false, isSmoothJoin: false);
        }
        geometry.Freeze();
        dc.DrawGeometry(brush, null, geometry);
    }

    private List<ScanResult> GetExternalDisplayResults()
    {
        var explicitNodes = _results
            .Where(r => IsPublicIpv4(r.IpAddress))
            .OrderBy(r => r.IpSortKey)
            .ToList();
        var known = explicitNodes.Select(r => r.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // A public IP observed once during the current NetLoom session remains part of the
        // topology until the user explicitly clears External history. This is independent from
        // the short LIVE activity window and from the start/end traffic-audit snapshot.
        var observed = _topologySignificanceSnapshot.ExternalNodes
            .Where(d => IsPublicIpv4(d.Node.IpAddress) && !known.Contains(d.Node.IpAddress))
            .OrderByDescending(d => d.ForceVisible)
            .ThenByDescending(d => d.Score)
            .ThenBy(d => string.Equals(d.Node.ServiceGroup, "Unknown", StringComparison.OrdinalIgnoreCase) ? "ZZZ" : d.Node.ServiceGroup, StringComparer.CurrentCultureIgnoreCase)
            .ThenByDescending(d => d.Node.Bytes)
            .Select(d =>
            {
                var n = d.Node;
                return new ScanResult
                {
                    IsOnline = true,
                    IpAddress = n.IpAddress,
                    HostName = string.IsNullOrWhiteSpace(n.ObservedHost)
                        ? $"{n.ServiceGroup} · 중요도 {d.Score}"
                        : $"{n.ServiceGroup} · {n.ObservedHost}",
                    DeviceType = DeviceType.Internet,
                    ClassificationConfidence = Math.Clamp(d.Score, 1, 100),
                    ClassificationEvidence = new[]
                    {
                        $"Topology significance {d.Score} · {(d.ForceVisible ? "보안 우선 표시" : "의미있는 Flow")}",
                        string.IsNullOrWhiteSpace(d.Reason) ? "" : $"표시 근거 · {d.Reason}",
                        $"External traffic observation · {n.Packets:N0} pkt · {n.BytesText} · internal peers {d.InternalPeerCount:N0}",
                        string.IsNullOrWhiteSpace(n.ObservedHost) ? "" : $"Observed host/SNI · {n.ObservedHost} · {n.ServiceGroup}",
                        string.IsNullOrWhiteSpace(n.IntelligenceText) ? "" : $"Offline intelligence · {n.IntelligenceText}",
                        string.IsNullOrWhiteSpace(n.LastPeerIp) ? "" : $"Last peer {n.LastPeerIp} · {n.ServiceText}"
                    }.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray(),
                    AuditGroupLabel = $"External · {n.ServiceGroup}",
                    AuditGroupExpression = "Significant Flow Rendering · retained passive observation · risk-forced visibility"
                };
            })
            .ToList();

        explicitNodes.AddRange(observed);
        return explicitNodes;
    }

    private static bool IsStrongInfrastructure(DeviceType type) => type is
        DeviceType.Router or DeviceType.Switch or DeviceType.Hub or DeviceType.AccessPoint or DeviceType.WifiExtender or DeviceType.Firewall;

    private static bool IsSpecialAsset(DeviceType type) => type is
        DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor or DeviceType.Printer;

    private Brush SpecialAssetBrush(DeviceType type) => new SolidColorBrush(type switch
    {
        DeviceType.Server => LightTheme ? Color.FromRgb(70, 106, 166) : Color.FromRgb(117, 153, 211),
        DeviceType.Nas => LightTheme ? Color.FromRgb(46, 130, 118) : Color.FromRgb(82, 177, 164),
        DeviceType.Hypervisor => LightTheme ? Color.FromRgb(102, 82, 160) : Color.FromRgb(145, 126, 196),
        DeviceType.Printer => LightTheme ? Color.FromRgb(95, 95, 95) : Color.FromRgb(205, 205, 205),
        _ => LightTheme ? Color.FromRgb(105, 90, 38) : Color.FromRgb(250, 216, 59)
    });

    private static int SpecialAssetOrder(DeviceType type) => type switch
    {
        DeviceType.Hypervisor => 0,
        DeviceType.Server => 1,
        DeviceType.Nas => 2,
        DeviceType.Printer => 3,
        _ => 9
    };

    private static int InfrastructureOrder(DeviceType type) => type switch
    {
        DeviceType.Firewall => 0,
        DeviceType.Router => 1,
        DeviceType.Switch => 2,
        DeviceType.Hub => 3,
        DeviceType.AccessPoint => 4,
        DeviceType.WifiExtender => 5,
        _ => 9
    };

    private static string MakeLabel(string ip, string hostName, bool isCenter, bool isSynthetic)
    {
        if (isSynthetic)
        {
            string second = string.IsNullOrWhiteSpace(hostName) ? "" : $"\n{Shorten(hostName, 22)}";
            return $"{Shorten(ip, 18)}{second}";
        }

        if (string.IsNullOrWhiteSpace(ip)) return isCenter ? "Gateway" : "장치";
        if (isCenter)
        {
            if (!string.IsNullOrWhiteSpace(hostName))
                return $"GW {ip}\n{Shorten(hostName.Split('.')[0], 18)}";
            return $"GW {ip}";
        }

        if (!string.IsNullOrWhiteSpace(hostName))
            return $"{Shorten(hostName.Split('.')[0], 15)}\n{ip}";
        return ip;
    }

    private static string Shorten(string value, int max)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= max) return value;
        return value[..Math.Max(1, max - 1)] + "…";
    }

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
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false; // CGNAT
        if (b[0] == 0 || b[0] >= 224) return false;
        return true;
    }

    private static SolidColorBrush BrushRgb((int R, int G, int B) c) =>
        new(Color.FromRgb((byte)c.R, (byte)c.G, (byte)c.B));

    private void DrawText(DrawingContext dc, string value, double size, FontWeight weight, Brush brush, Point point)
    {
        dc.DrawText(CreateText(value, size, weight, brush), point);
    }

    private FormattedText CreateText(string value, double size, FontWeight weight, Brush brush)
    {
        var dpi = VisualTreeHelper.GetDpi(this);
        return new FormattedText(
            value,
            CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, weight, FontStretches.Normal),
            size,
            brush,
            dpi.PixelsPerDip)
        {
            TextAlignment = TextAlignment.Left
        };
    }
}
