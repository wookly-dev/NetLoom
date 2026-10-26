using System.Net;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

/// <summary>
/// Passive, metadata-only relationship security analyzer fed from the same PacketObservation
/// stream used by the packet tracer/live traffic views. It does not inspect or retain raw packet
/// payloads. Findings are heuristics for audit triage and are not malware verdicts.
/// v0.6.5 adds DNS anomaly scoring, local analyst policy/allowlists and offline CIDR intelligence.
/// </summary>
public sealed class SecurityRelationshipAnalyzer
{
    private sealed class FlowAccumulator
    {
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public string SourceIp = "";
        public string DestinationIp = "";
        public string Protocol = "IP";
        public int? SourcePort;
        public int? DestinationPort;
        public long Packets;
        public long Bytes;
        public long ConnectionStarts;
        public long ConnectionEnds;
    }

    private sealed class TrafficMinuteBucket
    {
        public long ExternalBytes;
        public long OutboundBytes;
        public long InboundBytes;
        public long Packets;
    }

    private sealed class NodeAccumulator
    {
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public long ExternalPackets;
        public long ExternalBytes;
        public Dictionary<string, DateTime> ExternalPeers { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, DateTime> OutboundExternalFirstSeen { get; } = new(StringComparer.OrdinalIgnoreCase);
        public SortedDictionary<long, TrafficMinuteBucket> TrafficMinutes { get; } = new();
    }

    private sealed class BeaconAccumulator
    {
        public string InternalIp = "";
        public string ExternalIp = "";
        public string Protocol = "TCP";
        public int? DestinationPort;
        public Queue<DateTime> Attempts { get; } = new();
    }

    private sealed record ConnectionAttempt(DateTime TimestampUtc, string SourceIp, string DestinationIp, int? DestinationPort, bool DestinationExternal);
    private sealed record DnsObservation(DateTime TimestampUtc, string InternalIp, string QueryName, bool IsResponse, int ResponseCode);

    private static readonly HashSet<int> AttentionExternalPorts = new()
    {
        20, 21, 22, 23, 25, 110, 135, 137, 138, 139, 143, 389, 445, 465, 587, 636,
        873, 993, 995, 1433, 1521, 1883, 2049, 3306, 3389, 5060, 5061, 5432, 5900, 6379,
        8080, 8443, 8883, 9100
    };

    private static readonly HashSet<int> InternalManagementPorts = new()
    {
        22, 135, 139, 445, 3389, 5900, 5985, 5986
    };

    private readonly object _sync = new();
    private readonly Dictionary<string, FlowAccumulator> _flows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NodeAccumulator> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<ConnectionAttempt> _recentConnectionAttempts = new();
    private readonly Dictionary<string, BeaconAccumulator> _beaconAttempts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DnsObservation> _dnsObservations = new();
    private readonly Dictionary<string, string> _externalObservedHosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, SecurityNodeAssessment> _lastAssessments = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _lastBeaconFlowKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _lastBaselineAnomalyIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _lastLateralMovementIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _lastDnsAnomalyIps = new(StringComparer.OrdinalIgnoreCase);
    private readonly SecurityBehaviorBaselineService _baseline;
    private readonly SecurityPolicyService _policy;
    private readonly ExternalIntelligenceService _intelligence;
    private DateTime _sessionStartedUtc;
    private long _totalPackets;
    private long _totalBytes;

    public SecurityRelationshipAnalyzer(
        SecurityBehaviorBaselineService? baseline = null,
        SecurityPolicyService? policy = null,
        ExternalIntelligenceService? intelligence = null)
    {
        _baseline = baseline ?? new SecurityBehaviorBaselineService();
        _policy = policy ?? new SecurityPolicyService();
        _intelligence = intelligence ?? new ExternalIntelligenceService();
    }

    public string BaselineStoragePath => _baseline.StoragePath;
    public int BaselineDeviceCount => _baseline.DeviceCount;
    public string PolicyStoragePath => _policy.StoragePath;
    public string IntelligenceStoragePath => _intelligence.StoragePath;
    public int IntelligenceRecordCount => _intelligence.Count;
    public SecurityPolicyDocument GetPolicySnapshot() => _policy.Snapshot();
    public void SavePolicy(SecurityPolicyDocument document) => _policy.Save(document);
    public void ReloadPolicy() => _policy.Reload();
    public void ReloadIntelligence() => _intelligence.Reload();
    public void EnsureIntelligenceTemplate() => _intelligence.EnsureTemplate();

    public void Clear()
    {
        lock (_sync)
        {
            _flows.Clear();
            _nodes.Clear();
            _recentConnectionAttempts.Clear();
            _beaconAttempts.Clear();
            _dnsObservations.Clear();
            _externalObservedHosts.Clear();
            _lastAssessments.Clear();
            _lastBeaconFlowKeys.Clear();
            _lastBaselineAnomalyIps.Clear();
            _lastLateralMovementIps.Clear();
            _lastDnsAnomalyIps.Clear();
            _sessionStartedUtc = default;
            _totalPackets = 0;
            _totalBytes = 0;
        }
    }

    public void ClearBaseline()
    {
        lock (_sync)
        {
            _baseline.Reset();
            _lastBaselineAnomalyIps.Clear();
        }
    }

    public void FlushBaseline() => _baseline.Flush();

    public void Add(PacketObservation packet)
    {
        if (packet.Length <= 0 || string.IsNullOrWhiteSpace(packet.SourceIp) || string.IsNullOrWhiteSpace(packet.DestinationIp))
            return;

        bool sourcePrivate = IsPrivateIpv4(packet.SourceIp);
        bool destinationPrivate = IsPrivateIpv4(packet.DestinationIp);
        bool sourcePublic = IsPublicIpv4(packet.SourceIp);
        bool destinationPublic = IsPublicIpv4(packet.DestinationIp);

        lock (_sync)
        {
            if (_sessionStartedUtc == default)
                _sessionStartedUtc = packet.Timestamp;

            _totalPackets++;
            _totalBytes += packet.Length;

            string flowKey = FlowKey(packet.SourceIp, packet.DestinationIp, packet.Protocol, packet.DestinationPort);
            if (!_flows.TryGetValue(flowKey, out var flow))
            {
                flow = new FlowAccumulator
                {
                    FirstSeenUtc = packet.Timestamp,
                    LastSeenUtc = packet.Timestamp,
                    SourceIp = packet.SourceIp,
                    DestinationIp = packet.DestinationIp,
                    Protocol = packet.Protocol,
                    SourcePort = packet.SourcePort,
                    DestinationPort = packet.DestinationPort
                };
                _flows[flowKey] = flow;
            }

            flow.LastSeenUtc = packet.Timestamp;
            flow.SourcePort = packet.SourcePort;
            flow.Packets++;
            flow.Bytes += packet.Length;
            if (packet.IsTcpConnectionStart) flow.ConnectionStarts++;
            if (packet.IsTcpFin || packet.IsTcpRst) flow.ConnectionEnds++;

            if (sourcePrivate && destinationPublic)
                AddExternalRelationship(packet.SourceIp, packet.DestinationIp, packet.Timestamp, packet.Length, outbound: true);
            else if (sourcePublic && destinationPrivate)
                AddExternalRelationship(packet.DestinationIp, packet.SourceIp, packet.Timestamp, packet.Length, outbound: false);

            if (sourcePrivate && destinationPublic)
            {
                string observedHost = ExternalServiceClassifier.ExtractObservedHost(packet.ApplicationSummary);
                if (!string.IsNullOrWhiteSpace(observedHost))
                    _externalObservedHosts[packet.DestinationIp] = observedHost;
            }

            if (packet.IsDns && !string.IsNullOrWhiteSpace(packet.DnsQueryName))
            {
                string internalIp = packet.DnsIsResponse == true
                    ? (destinationPrivate ? packet.DestinationIp : "")
                    : (sourcePrivate ? packet.SourceIp : "");
                if (!string.IsNullOrWhiteSpace(internalIp))
                    _dnsObservations.Enqueue(new DnsObservation(packet.Timestamp, internalIp, packet.DnsQueryName, packet.DnsIsResponse == true, packet.DnsResponseCode ?? 0));
            }

            if (packet.IsTcpConnectionStart)
            {
                _recentConnectionAttempts.Enqueue(new ConnectionAttempt(
                    packet.Timestamp,
                    packet.SourceIp,
                    packet.DestinationIp,
                    packet.DestinationPort,
                    destinationPublic));

                if (sourcePrivate && destinationPublic)
                    AddBeaconAttempt(packet.SourceIp, packet.DestinationIp, packet.Protocol, packet.DestinationPort, packet.Timestamp);
            }

            Prune(packet.Timestamp);
        }
    }

    public PacketSecurityTag ClassifyPacket(PacketObservation packet)
    {
        bool sourcePrivate = IsPrivateIpv4(packet.SourceIp);
        bool destinationPrivate = IsPrivateIpv4(packet.DestinationIp);
        bool sourcePublic = IsPublicIpv4(packet.SourceIp);
        bool destinationPublic = IsPublicIpv4(packet.DestinationIp);
        bool external = (sourcePrivate && destinationPublic) || (sourcePublic && destinationPrivate);

        lock (_sync)
        {
            string externalIp = destinationPublic ? packet.DestinationIp : sourcePublic ? packet.SourceIp : "";
            string observedHost = ExternalServiceClassifier.ExtractObservedHost(packet.ApplicationSummary);
            if (string.IsNullOrWhiteSpace(observedHost) &&
                !string.IsNullOrWhiteSpace(externalIp) &&
                _externalObservedHosts.TryGetValue(externalIp, out string? knownHost))
            {
                observedHost = knownHost ?? "";
            }
            string serviceGroup = ExternalServiceClassifier.ClassifyHost(observedHost);
            int? servicePort = destinationPublic ? packet.DestinationPort : sourcePublic ? packet.SourcePort : packet.DestinationPort ?? packet.SourcePort;
            bool policyException = external && _policy.IsExternalAllowed(externalIp, observedHost, serviceGroup, servicePort);
            bool attentionPort = external && !policyException && IsAttentionPort(servicePort);

            SecurityNodeAssessment? sourceAssessment = _lastAssessments.TryGetValue(packet.SourceIp, out var source) ? source : null;
            SecurityNodeAssessment? destinationAssessment = _lastAssessments.TryGetValue(packet.DestinationIp, out var destination) ? destination : null;
            var strongest = new[] { sourceAssessment, destinationAssessment }
                .Where(x => x is not null)
                .OrderByDescending(x => x!.RiskScore)
                .FirstOrDefault();

            bool beacon = !policyException && _lastBeaconFlowKeys.Contains(FlowKey(packet.SourceIp, packet.DestinationIp, packet.Protocol, packet.DestinationPort));
            bool baselineAnomaly = _lastBaselineAnomalyIps.Contains(packet.SourceIp) || _lastBaselineAnomalyIps.Contains(packet.DestinationIp);
            bool lateral = !_policy.IsTrustedInternal(packet.SourceIp) && _lastLateralMovementIps.Contains(packet.SourceIp) &&
                           destinationPrivate && IsInternalManagementPort(packet.DestinationPort);
            string dnsInternalIp = packet.DnsIsResponse == true ? packet.DestinationIp : packet.SourceIp;
            bool dnsAnomaly = packet.IsDns && _lastDnsAnomalyIps.Contains(dnsInternalIp);

            bool suspicious = attentionPort || beacon || baselineAnomaly || lateral || dnsAnomaly || (strongest?.RiskScore ?? 0) >= 25;
            var reasons = new List<string>();
            if (dnsAnomaly) reasons.Add("DNS 이상 패턴 후보");
            if (beacon) reasons.Add("주기적 Beaconing 후보");
            if (baselineAnomaly) reasons.Add("정상 행동 Baseline 이탈");
            if (lateral) reasons.Add("내부 횡적 이동 후보");
            if (attentionPort) reasons.Add($"외부 주의 포트 · {TrafficAuditFlowRecord.DescribeService(packet.Protocol, servicePort)}");
            if (policyException) reasons.Add("보안 정책 Allowlist 일치");
            if (reasons.Count == 0 && suspicious && strongest is not null)
                reasons.AddRange(strongest.Reasons.Take(2));

            string level = strongest?.RiskLevel ?? (attentionPort || beacon || baselineAnomaly || lateral || dnsAnomaly ? "WATCH" : "NORMAL");
            if ((attentionPort || beacon || baselineAnomaly || lateral || dnsAnomaly) && string.Equals(level, "NORMAL", StringComparison.OrdinalIgnoreCase))
                level = "WATCH";

            return new PacketSecurityTag
            {
                IsExternal = external,
                IsSuspicious = suspicious,
                IsBeaconCandidate = beacon,
                IsBaselineAnomaly = baselineAnomaly,
                IsLateralMovementCandidate = lateral,
                IsDnsAnomaly = dnsAnomaly,
                IsPolicyException = policyException,
                RiskLevel = level,
                Reason = string.Join(" / ", reasons)
            };
        }
    }

    public SecurityRelationshipSnapshot TakeSnapshot(int maxNodes = 512, int maxFlows = 256)
    {
        lock (_sync)
        {
            var now = DateTime.UtcNow;
            Prune(now);

            // Build sliding-window indexes once per UI snapshot. The UI asks for a snapshot about
            // twice per second, so avoid O(nodes * packets/flows) work on busy office networks.
            var attempts = _recentConnectionAttempts.ToArray();
            var recent5m = now - TimeSpan.FromMinutes(5);
            var recent60s = now - TimeSpan.FromSeconds(60);

            var externalAttempts5m = attempts
                .Where(a => a.TimestampUtc >= recent5m && a.DestinationExternal && IsPrivateIpv4(a.SourceIp))
                .GroupBy(a => a.SourceIp, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);

            var externalFanOutBySource = externalAttempts5m.ToDictionary(
                pair => pair.Key,
                pair => pair.Value.Select(a => a.DestinationIp).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                StringComparer.OrdinalIgnoreCase);

            var internalAttemptBySource60s = attempts
                .Where(a => a.TimestampUtc >= recent60s && IsPrivateIpv4(a.SourceIp) && IsPrivateIpv4(a.DestinationIp))
                .GroupBy(a => a.SourceIp, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);

            var internalManagementBySource5m = attempts
                .Where(a => a.TimestampUtc >= recent5m && IsPrivateIpv4(a.SourceIp) && IsPrivateIpv4(a.DestinationIp) && IsInternalManagementPort(a.DestinationPort))
                .GroupBy(a => a.SourceIp, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);

            var dnsByInternal5m = _dnsObservations
                .Where(d => d.TimestampUtc >= recent5m)
                .GroupBy(d => d.InternalIp, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.ToArray(), StringComparer.OrdinalIgnoreCase);

            var beaconCandidates = BuildBeaconCandidates(now);
            var beaconsByInternal = beaconCandidates
                .GroupBy(b => b.InternalIp, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.ConfidenceScore).ThenBy(x => x.JitterPercent).ToArray(), StringComparer.OrdinalIgnoreCase);

            var flowsSnapshot = _flows.Values.ToArray();
            var flowsByPrivateIp = new Dictionary<string, List<FlowAccumulator>>(StringComparer.OrdinalIgnoreCase);
            foreach (var flow in flowsSnapshot)
            {
                if (IsPrivateIpv4(flow.SourceIp))
                    AddFlowIndex(flowsByPrivateIp, flow.SourceIp, flow);
                if (IsPrivateIpv4(flow.DestinationIp) && !string.Equals(flow.SourceIp, flow.DestinationIp, StringComparison.OrdinalIgnoreCase))
                    AddFlowIndex(flowsByPrivateIp, flow.DestinationIp, flow);
            }

            var assessments = new List<SecurityNodeAssessment>();
            var findings = new List<SecurityRelationshipFinding>();

            var candidateIps = _nodes.Keys
                .Concat(externalFanOutBySource.Keys)
                .Concat(internalAttemptBySource60s.Keys)
                .Concat(internalManagementBySource5m.Keys)
                .Concat(dnsByInternal5m.Keys)
                .Concat(beaconsByInternal.Keys)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(Math.Clamp(maxNodes, 1, 4096))
                .ToArray();

            foreach (string ip in candidateIps)
            {
                _nodes.TryGetValue(ip, out var node);
                int fanOut = externalFanOutBySource.TryGetValue(ip, out int fanOutValue) ? fanOutValue : 0;
                int externalStarts5m = externalAttempts5m.TryGetValue(ip, out var extAttempts) ? extAttempts.Length : 0;
                bool trustedInternal = _policy.IsTrustedInternal(ip);

                var distinctExternalAttempts = (extAttempts ?? Array.Empty<ConnectionAttempt>())
                    .GroupBy(a => a.DestinationIp, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.OrderByDescending(x => x.TimestampUtc).First())
                    .ToArray();
                int unapprovedFanOut = distinctExternalAttempts.Count(a => !IsExternalAllowedPeer(a.DestinationIp, a.DestinationPort));
                int policyAllowedExternalCount = Math.Max(0, fanOut - unapprovedFanOut);

                var internalAttempts60s = internalAttemptBySource60s.TryGetValue(ip, out var internalAttempts)
                    ? internalAttempts
                    : Array.Empty<ConnectionAttempt>();
                int hostSweepTargets = internalAttempts60s
                    .Select(a => a.DestinationIp)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
                int portSweepPorts = internalAttempts60s
                    .GroupBy(a => a.DestinationIp, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.Where(a => a.DestinationPort.HasValue).Select(a => a.DestinationPort!.Value).Distinct().Count())
                    .DefaultIfEmpty(0)
                    .Max();

                var managementAttempts5m = internalManagementBySource5m.TryGetValue(ip, out var managementAttempts)
                    ? managementAttempts
                    : Array.Empty<ConnectionAttempt>();
                int lateralTargets = managementAttempts5m
                    .Select(a => a.DestinationIp)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();

                var relatedFlows = flowsByPrivateIp.TryGetValue(ip, out var indexedFlows)
                    ? indexedFlows
                    : EmptyFlowList;
                var externalFlows = relatedFlows.Where(IsExternalFlow).ToArray();
                int longLived = externalFlows.Count(f => IsLongLivedFlow(f, now) && !IsFlowPolicyAllowed(f));
                int suspiciousPorts = externalFlows
                    .Where(f => !IsFlowPolicyAllowed(f) && IsAttentionPort(f.DestinationPort ?? f.SourcePort))
                    .Select(f => f.DestinationPort ?? f.SourcePort)
                    .Where(p => p.HasValue)
                    .Distinct()
                    .Count();

                var externalPeers = node?.ExternalPeers.Keys.ToArray() ?? externalFlows
                    .Select(f => string.Equals(f.SourceIp, ip, StringComparison.OrdinalIgnoreCase) ? f.DestinationIp : f.SourceIp)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                int externalPeerCount = externalPeers.Length;
                int recentNewExternal = node?.OutboundExternalFirstSeen.Count(p => p.Value >= now - TimeSpan.FromMinutes(10) && !IsExternalAllowedPeer(p.Key, null)) ?? 0;
                int intelWatchCount = 0;
                int intelSuspiciousCount = 0;
                foreach (string peer in externalPeers)
                {
                    var intel = _intelligence.Lookup(peer);
                    if (intel is null) continue;
                    if (string.Equals(intel.Classification, "SUSPICIOUS", StringComparison.OrdinalIgnoreCase)) intelSuspiciousCount++;
                    else if (string.Equals(intel.Classification, "WATCH", StringComparison.OrdinalIgnoreCase)) intelWatchCount++;
                }

                var dnsEvents = dnsByInternal5m.TryGetValue(ip, out var dns) ? dns : Array.Empty<DnsObservation>();
                var dnsQueries = dnsEvents.Where(d => !d.IsResponse && !_policy.IsDomainAllowed(d.QueryName)).ToArray();
                var dnsResponses = dnsEvents.Where(d => d.IsResponse && !_policy.IsDomainAllowed(d.QueryName)).ToArray();
                int dnsQueryCount = dnsQueries.Length;
                int dnsUniqueQueryCount = dnsQueries.Select(d => d.QueryName).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                int dnsNxDomainCount = dnsResponses.Count(d => d.ResponseCode == 3);
                int dnsDenominator = Math.Max(dnsQueryCount, dnsResponses.Length);
                double dnsNxRatio = dnsDenominator <= 0 ? 0 : Math.Clamp(dnsNxDomainCount * 100.0 / dnsDenominator, 0, 100);
                var dnsThresholds = _policy.DnsThresholds;
                int dnsLongQueryCount = dnsQueries.Count(d => d.QueryName.Length >= dnsThresholds.LongQueryLength);
                int dnsMaxQueryLength = dnsQueries.Select(d => d.QueryName.Length).DefaultIfEmpty(0).Max();
                int dnsAnomalyScore = 0;
                if (dnsDenominator >= dnsThresholds.MinimumQueries)
                {
                    if (dnsNxRatio >= dnsThresholds.NxDomainRatioPercent) dnsAnomalyScore += 35;
                    else if (dnsNxRatio >= dnsThresholds.NxDomainRatioPercent * 0.65) dnsAnomalyScore += 18;
                    if (dnsUniqueQueryCount >= 120) dnsAnomalyScore += 18;
                    else if (dnsUniqueQueryCount >= 60) dnsAnomalyScore += 10;
                }
                if (dnsLongQueryCount >= dnsThresholds.LongQueryCount) dnsAnomalyScore += 35;
                else if (dnsLongQueryCount >= Math.Max(2, dnsThresholds.LongQueryCount / 2)) dnsAnomalyScore += 18;
                if (dnsMaxQueryLength >= 180) dnsAnomalyScore += 15;
                dnsAnomalyScore = Math.Clamp(dnsAnomalyScore, 0, 100);

                var traffic5m = GetTraffic5m(node, now);
                double uploadRatio = traffic5m.ExternalBytes <= 0
                    ? 0
                    : Math.Clamp(traffic5m.OutboundBytes * 100.0 / traffic5m.ExternalBytes, 0, 100);

                var behaviorSample = new SecurityBehaviorSample
                {
                    ExternalFanOut5m = fanOut,
                    ExternalConnectionStarts5m = externalStarts5m,
                    ExternalBytes5m = traffic5m.ExternalBytes,
                    OutboundExternalBytes5m = traffic5m.OutboundBytes,
                    InternalManagementTargets5m = lateralTargets
                };
                SecurityBaselineEvaluation baseline = _baseline.Evaluate(ip, now, behaviorSample);

                var nodeBeacons = (beaconsByInternal.TryGetValue(ip, out var b) ? b : Array.Empty<BeaconCandidate>())
                    .Where(candidate => !IsExternalAllowedPeer(candidate.ExternalIp, candidate.DestinationPort))
                    .ToArray();
                BeaconCandidate? strongestBeacon = nodeBeacons.FirstOrDefault();

                int score = 0;
                var reasons = new List<string>();

                if (unapprovedFanOut >= 50) { score += 28; reasons.Add($"미승인 외부 fan-out {unapprovedFanOut}개/5분"); }
                else if (unapprovedFanOut >= 25) { score += 20; reasons.Add($"미승인 외부 fan-out {unapprovedFanOut}개/5분"); }
                else if (unapprovedFanOut >= 15) { score += 12; reasons.Add($"미승인 외부 fan-out {unapprovedFanOut}개/5분"); }
                if (policyAllowedExternalCount > 0) reasons.Add($"정책 Allowlist 외부 목적지 {policyAllowedExternalCount}개 제외");

                if (recentNewExternal >= 30) { score += 18; reasons.Add($"신규 외부 목적지 {recentNewExternal}개/10분"); }
                else if (recentNewExternal >= 15) { score += 10; reasons.Add($"신규 외부 목적지 {recentNewExternal}개/10분"); }

                if (longLived > 0)
                {
                    score += Math.Min(18, 8 + longLived * 3);
                    reasons.Add($"장시간 지속/반복 외부 흐름 {longLived}개");
                }

                if (suspiciousPorts > 0)
                {
                    score += Math.Min(30, 20 + suspiciousPorts * 5);
                    reasons.Add($"외부 주의 포트 {suspiciousPorts}종");
                }

                if (!trustedInternal)
                {
                    if (hostSweepTargets >= 30) { score += 45; reasons.Add($"내부 host sweep 후보 {hostSweepTargets}대/60초"); }
                    else if (hostSweepTargets >= 12) { score += 32; reasons.Add($"내부 host sweep 후보 {hostSweepTargets}대/60초"); }

                    if (portSweepPorts >= 20) { score += 40; reasons.Add($"port sweep 후보 {portSweepPorts}포트/60초"); }
                    else if (portSweepPorts >= 10) { score += 30; reasons.Add($"port sweep 후보 {portSweepPorts}포트/60초"); }

                    if (lateralTargets >= 20) { score += 45; reasons.Add($"내부 횡적 이동 후보 {lateralTargets}대/5분"); }
                    else if (lateralTargets >= 8) { score += 30; reasons.Add($"내부 횡적 이동 후보 {lateralTargets}대/5분"); }
                    else if (lateralTargets >= 4) { score += 18; reasons.Add($"내부 관리포트 확산 {lateralTargets}대/5분"); }
                }
                else if (hostSweepTargets >= 12 || portSweepPorts >= 10 || lateralTargets >= 4)
                {
                    reasons.Add("정책 신뢰 내부 장비 · 관리/스캔 확산 위험점수 제외");
                }

                if (strongestBeacon is not null)
                {
                    int beaconRisk = strongestBeacon.ConfidenceScore >= 80 ? 28 : strongestBeacon.ConfidenceScore >= 65 ? 20 : 14;
                    score += beaconRisk;
                    reasons.Add($"Beaconing 후보 {strongestBeacon.ExternalIp}:{strongestBeacon.DestinationPort?.ToString() ?? "-"} · {strongestBeacon.IntervalText} · jitter {strongestBeacon.JitterPercent:0.0}%");
                }

                if (dnsAnomalyScore >= 60)
                {
                    score += 25;
                    reasons.Add($"DNS 이상 {dnsAnomalyScore}/100 · NXDOMAIN {dnsNxRatio:0}% · 긴 질의 {dnsLongQueryCount}개");
                }
                else if (dnsAnomalyScore >= 30)
                {
                    score += 15;
                    reasons.Add($"DNS 이상 후보 {dnsAnomalyScore}/100 · NXDOMAIN {dnsNxRatio:0}% · 긴 질의 {dnsLongQueryCount}개");
                }

                if (intelSuspiciousCount > 0)
                {
                    score += Math.Min(35, 25 + (intelSuspiciousCount - 1) * 5);
                    reasons.Add($"로컬 인텔리전스 SUSPICIOUS 목적지 {intelSuspiciousCount}개");
                }
                else if (intelWatchCount > 0)
                {
                    score += Math.Min(20, 10 + (intelWatchCount - 1) * 3);
                    reasons.Add($"로컬 인텔리전스 WATCH 목적지 {intelWatchCount}개");
                }

                if (baseline.IsReady && baseline.AnomalyScore >= 55)
                {
                    score += 24;
                    reasons.Add($"Baseline 이탈 {baseline.AnomalyScore}/100 · {string.Join(", ", baseline.Reasons.Take(2))}");
                }
                else if (baseline.IsReady && baseline.AnomalyScore >= 30)
                {
                    score += 12;
                    reasons.Add($"Baseline 편차 {baseline.AnomalyScore}/100 · {string.Join(", ", baseline.Reasons.Take(2))}");
                }

                if (traffic5m.ExternalBytes >= 50L * 1024 * 1024 && uploadRatio >= 90)
                {
                    score += 18;
                    reasons.Add($"외부 송신 편중 {TrafficAuditFlowRecord.FormatBytes(traffic5m.OutboundBytes)}/5분 · {uploadRatio:0}%");
                }
                else if (traffic5m.ExternalBytes >= 10L * 1024 * 1024 && uploadRatio >= 92)
                {
                    score += 10;
                    reasons.Add($"외부 송신 비율 높음 {uploadRatio:0}%/5분");
                }

                // Phase-2 behavioral signals are audit-worthy on their own. Keep them at least
                // WATCH so 2D/3D overlays, packet filters and reports do not disagree about severity.
                if ((strongestBeacon is not null || (!trustedInternal && lateralTargets >= 4) || dnsAnomalyScore >= 30 || intelSuspiciousCount > 0 || intelWatchCount > 0 ||
                     (baseline.IsReady && baseline.AnomalyScore >= 30)) && score < 25)
                    score = 25;

                score = Math.Clamp(score, 0, 100);
                string level = ToRiskLevel(score);

                var assessment = new SecurityNodeAssessment
                {
                    IpAddress = ip,
                    RiskScore = score,
                    RiskLevel = level,
                    FirstSeenUtc = node?.FirstSeenUtc ?? relatedFlows.Select(f => f.FirstSeenUtc).DefaultIfEmpty(now).Min(),
                    LastSeenUtc = node?.LastSeenUtc ?? relatedFlows.Select(f => f.LastSeenUtc).DefaultIfEmpty(now).Max(),
                    ExternalPeerCount = externalPeerCount,
                    RecentNewExternalCount = recentNewExternal,
                    FanOutExternalCount = fanOut,
                    UnapprovedExternalFanOutCount = unapprovedFanOut,
                    PolicyAllowedExternalCount = policyAllowedExternalCount,
                    PolicyTrustedInternal = trustedInternal,
                    ExternalIntelWatchCount = intelWatchCount,
                    ExternalIntelSuspiciousCount = intelSuspiciousCount,
                    LongLivedFlowCount = longLived,
                    SuspiciousExternalPortCount = suspiciousPorts,
                    HostSweepTargetCount = hostSweepTargets,
                    PortSweepPortCount = portSweepPorts,
                    ExternalConnectionStarts5m = externalStarts5m,
                    ExternalBytes5m = traffic5m.ExternalBytes,
                    OutboundExternalBytes5m = traffic5m.OutboundBytes,
                    InboundExternalBytes5m = traffic5m.InboundBytes,
                    UploadRatioPercent = uploadRatio,
                    LateralMovementTargetCount = lateralTargets,
                    DnsQueryCount5m = dnsQueryCount,
                    DnsUniqueQueryCount5m = dnsUniqueQueryCount,
                    DnsNxDomainCount5m = dnsNxDomainCount,
                    DnsNxDomainRatioPercent = dnsNxRatio,
                    DnsLongQueryCount5m = dnsLongQueryCount,
                    DnsMaxQueryLength = dnsMaxQueryLength,
                    DnsAnomalyScore = dnsAnomalyScore,
                    BeaconCandidateCount = nodeBeacons.Length,
                    BeaconExternalIp = strongestBeacon?.ExternalIp ?? "",
                    BeaconDestinationPort = strongestBeacon?.DestinationPort,
                    BeaconIntervalSeconds = strongestBeacon?.IntervalSeconds ?? 0,
                    BeaconJitterPercent = strongestBeacon?.JitterPercent ?? 0,
                    BeaconConfidenceScore = strongestBeacon?.ConfidenceScore ?? 0,
                    BaselineReady = baseline.IsReady,
                    BaselineSampleCount = baseline.SampleCount,
                    BaselineScopeText = baseline.ScopeText,
                    BaselineAnomalyScore = baseline.AnomalyScore,
                    BaselineReasons = baseline.Reasons,
                    ExternalPackets = node?.ExternalPackets ?? externalFlows.Sum(f => f.Packets),
                    ExternalBytes = node?.ExternalBytes ?? externalFlows.Sum(f => f.Bytes),
                    Reasons = reasons
                };
                assessments.Add(assessment);
                BuildFindings(assessment, findings);

                bool eligibleForLearning = score < 25 && baseline.AnomalyScore < 30 && dnsAnomalyScore < 30 &&
                                           suspiciousPorts == 0 && intelSuspiciousCount == 0 &&
                                           (trustedInternal || (hostSweepTargets < 12 && portSweepPorts < 10 && lateralTargets < 4)) && strongestBeacon is null;
                _baseline.TryLearn(ip, now, behaviorSample, eligibleForLearning);
            }

            _lastAssessments.Clear();
            _lastBaselineAnomalyIps.Clear();
            _lastLateralMovementIps.Clear();
            _lastDnsAnomalyIps.Clear();
            foreach (var assessment in assessments)
            {
                _lastAssessments[assessment.IpAddress] = assessment;
                if (assessment.BaselineReady && assessment.BaselineAnomalyScore >= 30)
                    _lastBaselineAnomalyIps.Add(assessment.IpAddress);
                if (!assessment.PolicyTrustedInternal && assessment.LateralMovementTargetCount >= 4)
                    _lastLateralMovementIps.Add(assessment.IpAddress);
                if (assessment.DnsAnomalyScore >= 30)
                    _lastDnsAnomalyIps.Add(assessment.IpAddress);
            }

            _lastBeaconFlowKeys.Clear();
            foreach (var beacon in beaconCandidates.Where(b => !IsExternalAllowedPeer(b.ExternalIp, b.DestinationPort)))
                _lastBeaconFlowKeys.Add(FlowKey(beacon.InternalIp, beacon.ExternalIp, beacon.Protocol, beacon.DestinationPort));

            var assessmentByIp = assessments.ToDictionary(a => a.IpAddress, StringComparer.OrdinalIgnoreCase);
            var suspiciousFlows = flowsSnapshot
                .Select(flow => BuildFlowAssessment(flow, assessmentByIp, now, _lastBeaconFlowKeys))
                .Where(flow => flow.RiskScore >= 15 || flow.IsSuspiciousPort || flow.IsLongLived)
                .OrderByDescending(flow => flow.RiskScore)
                .ThenByDescending(flow => flow.Bytes)
                .Take(Math.Clamp(maxFlows, 1, 2048))
                .ToArray();

            return new SecurityRelationshipSnapshot
            {
                SessionStartedUtc = _sessionStartedUtc,
                TimestampUtc = now,
                TotalPackets = _totalPackets,
                TotalBytes = _totalBytes,
                Nodes = assessments.OrderByDescending(n => n.RiskScore).ThenByDescending(n => n.ExternalBytes).ToArray(),
                SuspiciousFlows = suspiciousFlows,
                Findings = findings.OrderByDescending(f => SeverityOrder(f.Severity)).ThenByDescending(f => f.Score).ThenBy(f => f.IpAddress, StringComparer.OrdinalIgnoreCase).ToArray(),
                BeaconCandidates = beaconCandidates.OrderByDescending(b => b.ConfidenceScore).ThenBy(b => b.JitterPercent).Take(256).ToArray()
            };
        }
    }

    private static readonly List<FlowAccumulator> EmptyFlowList = new();

    private static void AddFlowIndex(Dictionary<string, List<FlowAccumulator>> index, string ip, FlowAccumulator flow)
    {
        if (!index.TryGetValue(ip, out var list))
        {
            list = new List<FlowAccumulator>();
            index[ip] = list;
        }
        list.Add(flow);
    }

    private void AddExternalRelationship(string internalIp, string externalIp, DateTime timestamp, int length, bool outbound)
    {
        if (!_nodes.TryGetValue(internalIp, out var node))
        {
            node = new NodeAccumulator { FirstSeenUtc = timestamp, LastSeenUtc = timestamp };
            _nodes[internalIp] = node;
        }
        node.LastSeenUtc = timestamp;
        node.ExternalPackets++;
        node.ExternalBytes += length;
        node.ExternalPeers[externalIp] = timestamp;
        if (outbound && !node.OutboundExternalFirstSeen.ContainsKey(externalIp))
            node.OutboundExternalFirstSeen[externalIp] = timestamp;

        long minute = timestamp.Ticks / TimeSpan.TicksPerMinute;
        if (!node.TrafficMinutes.TryGetValue(minute, out var bucket))
        {
            bucket = new TrafficMinuteBucket();
            node.TrafficMinutes[minute] = bucket;
        }
        bucket.ExternalBytes += length;
        bucket.Packets++;
        if (outbound) bucket.OutboundBytes += length;
        else bucket.InboundBytes += length;
    }

    private void AddBeaconAttempt(string internalIp, string externalIp, string protocol, int? destinationPort, DateTime timestamp)
    {
        string key = FlowKey(internalIp, externalIp, protocol, destinationPort);
        if (!_beaconAttempts.TryGetValue(key, out var beacon))
        {
            beacon = new BeaconAccumulator
            {
                InternalIp = internalIp,
                ExternalIp = externalIp,
                Protocol = protocol,
                DestinationPort = destinationPort
            };
            _beaconAttempts[key] = beacon;
        }
        beacon.Attempts.Enqueue(timestamp);
        while (beacon.Attempts.Count > 128)
            beacon.Attempts.Dequeue();
    }

    private IReadOnlyList<BeaconCandidate> BuildBeaconCandidates(DateTime now)
    {
        var result = new List<BeaconCandidate>();
        foreach (var beacon in _beaconAttempts.Values)
        {
            var times = beacon.Attempts.Where(t => t >= now - TimeSpan.FromHours(2)).OrderBy(t => t).ToArray();
            if (times.Length < 6) continue;

            var intervals = new List<double>(times.Length - 1);
            for (int i = 1; i < times.Length; i++)
            {
                double seconds = (times[i] - times[i - 1]).TotalSeconds;
                if (seconds >= 15 && seconds <= 1800)
                    intervals.Add(seconds);
            }
            if (intervals.Count < 5) continue;

            double median = Median(intervals);
            if (median < 15 || median > 1800) continue;
            double mad = intervals.Select(v => Math.Abs(v - median)).Average();
            double jitter = median <= 0 ? 100 : mad / median * 100.0;
            if (jitter > 22) continue;

            int confidence = 25;
            confidence += intervals.Count >= 12 ? 20 : intervals.Count >= 8 ? 14 : 8;
            confidence += jitter <= 4 ? 35 : jitter <= 8 ? 28 : jitter <= 14 ? 20 : 12;
            if ((times[^1] - times[0]) >= TimeSpan.FromMinutes(15)) confidence += 12;
            if (IsAttentionPort(beacon.DestinationPort)) confidence += 8;
            confidence = Math.Clamp(confidence, 0, 100);
            if (confidence < 55) continue;

            result.Add(new BeaconCandidate
            {
                InternalIp = beacon.InternalIp,
                ExternalIp = beacon.ExternalIp,
                Protocol = beacon.Protocol,
                DestinationPort = beacon.DestinationPort,
                ObservationCount = times.Length,
                IntervalSeconds = median,
                JitterPercent = jitter,
                FirstSeenUtc = times[0],
                LastSeenUtc = times[^1],
                ConfidenceScore = confidence
            });
        }
        return result;
    }

    private static (long ExternalBytes, long OutboundBytes, long InboundBytes) GetTraffic5m(NodeAccumulator? node, DateTime now)
    {
        if (node is null || node.TrafficMinutes.Count == 0) return (0, 0, 0);
        long minMinute = (now - TimeSpan.FromMinutes(5)).Ticks / TimeSpan.TicksPerMinute;
        long external = 0, outbound = 0, inbound = 0;
        foreach (var pair in node.TrafficMinutes)
        {
            if (pair.Key < minMinute) continue;
            external += pair.Value.ExternalBytes;
            outbound += pair.Value.OutboundBytes;
            inbound += pair.Value.InboundBytes;
        }
        return (external, outbound, inbound);
    }

    private void Prune(DateTime now)
    {
        while (_recentConnectionAttempts.Count > 0 && _recentConnectionAttempts.Peek().TimestampUtc < now - TimeSpan.FromMinutes(10))
            _recentConnectionAttempts.Dequeue();
        while (_recentConnectionAttempts.Count > 50000)
            _recentConnectionAttempts.Dequeue();

        while (_dnsObservations.Count > 0 && _dnsObservations.Peek().TimestampUtc < now - TimeSpan.FromMinutes(10))
            _dnsObservations.Dequeue();
        while (_dnsObservations.Count > 100000)
            _dnsObservations.Dequeue();

        DateTime beaconCutoff = now - TimeSpan.FromHours(2);
        foreach (var key in _beaconAttempts.Keys.ToArray())
        {
            var beacon = _beaconAttempts[key];
            while (beacon.Attempts.Count > 0 && beacon.Attempts.Peek() < beaconCutoff)
                beacon.Attempts.Dequeue();
            if (beacon.Attempts.Count == 0)
                _beaconAttempts.Remove(key);
        }
        if (_beaconAttempts.Count > 8192)
        {
            foreach (var key in _beaconAttempts
                         .OrderBy(kv => kv.Value.Attempts.Count == 0 ? DateTime.MinValue : kv.Value.Attempts.Last())
                         .Take(_beaconAttempts.Count - 6144)
                         .Select(kv => kv.Key)
                         .ToArray())
                _beaconAttempts.Remove(key);
        }

        long minuteCutoff = (now - TimeSpan.FromHours(2)).Ticks / TimeSpan.TicksPerMinute;
        foreach (var node in _nodes.Values)
        {
            foreach (long key in node.TrafficMinutes.Keys.TakeWhile(k => k < minuteCutoff).ToArray())
                node.TrafficMinutes.Remove(key);
        }

        if (_flows.Count > 20000)
        {
            foreach (var key in _flows.OrderBy(kv => kv.Value.LastSeenUtc).Take(_flows.Count - 15000).Select(kv => kv.Key).ToArray())
                _flows.Remove(key);
        }
        if (_nodes.Count > 4096)
        {
            foreach (var key in _nodes.OrderBy(kv => kv.Value.LastSeenUtc).Take(_nodes.Count - 3072).Select(kv => kv.Key).ToArray())
                _nodes.Remove(key);
        }
    }

    private SecurityFlowAssessment BuildFlowAssessment(
        FlowAccumulator flow,
        IReadOnlyDictionary<string, SecurityNodeAssessment> assessments,
        DateTime now,
        IReadOnlySet<string> beaconFlowKeys)
    {
        bool external = IsExternalFlow(flow);
        bool policyAllowed = external && IsFlowPolicyAllowed(flow);
        bool longLived = !policyAllowed && IsLongLivedFlow(flow, now);
        bool suspiciousPort = external && !policyAllowed && IsAttentionPort(flow.DestinationPort ?? flow.SourcePort);
        bool beacon = beaconFlowKeys.Contains(FlowKey(flow.SourceIp, flow.DestinationIp, flow.Protocol, flow.DestinationPort));
        int sourceRisk = assessments.TryGetValue(flow.SourceIp, out var sourceAssessment) ? sourceAssessment.RiskScore : 0;
        int destinationRisk = assessments.TryGetValue(flow.DestinationIp, out var destinationAssessment) ? destinationAssessment.RiskScore : 0;
        int relatedNodeRisk = Math.Max(sourceRisk, destinationRisk);
        int risk = policyAllowed ? 0 : relatedNodeRisk / 2;
        var reasons = new List<string>();
        if (!policyAllowed && relatedNodeRisk >= 25) reasons.Add($"연관 노드 Risk {relatedNodeRisk}");
        if (suspiciousPort) { risk += 20; reasons.Add("외부 주의 포트"); }
        if (longLived) { risk += 12; reasons.Add("장시간 지속/반복"); }
        if (beacon) { risk += 25; reasons.Add("주기적 Beaconing 후보"); }
        risk = Math.Clamp(risk, 0, 100);
        return new SecurityFlowAssessment
        {
            FirstSeenUtc = flow.FirstSeenUtc,
            LastSeenUtc = flow.LastSeenUtc,
            SourceIp = flow.SourceIp,
            DestinationIp = flow.DestinationIp,
            Protocol = flow.Protocol,
            SourcePort = flow.SourcePort,
            DestinationPort = flow.DestinationPort,
            Packets = flow.Packets,
            Bytes = flow.Bytes,
            ConnectionStarts = flow.ConnectionStarts,
            ConnectionEnds = flow.ConnectionEnds,
            IsExternal = external,
            IsLongLived = longLived,
            IsSuspiciousPort = suspiciousPort,
            RiskScore = risk,
            RiskLevel = ToRiskLevel(risk),
            Reason = string.Join(" · ", reasons)
        };
    }

    private static void BuildFindings(SecurityNodeAssessment a, List<SecurityRelationshipFinding> findings)
    {
        if (!a.PolicyTrustedInternal && a.HostSweepTargetCount >= 12)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.HostSweepTargetCount >= 30 ? "HIGH" : "MEDIUM",
                Code = "HOST_SWEEP",
                IpAddress = a.IpAddress,
                Title = "내부 Host Sweep 후보",
                Evidence = $"최근 60초 TCP SYN 기준 서로 다른 내부 목적지 {a.HostSweepTargetCount}대 접근",
                Recommendation = "해당 장비의 실행 프로세스/관리 도구/EDR 로그를 확인하고 승인된 스캐너 여부를 검증",
                Score = a.RiskScore
            });
        }
        if (!a.PolicyTrustedInternal && a.PortSweepPortCount >= 10)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.PortSweepPortCount >= 20 ? "HIGH" : "MEDIUM",
                Code = "PORT_SWEEP",
                IpAddress = a.IpAddress,
                Title = "Port Sweep 후보",
                Evidence = $"최근 60초 TCP SYN 기준 단일 내부 대상에 최대 {a.PortSweepPortCount}개 목적지 포트 접근",
                Recommendation = "승인된 진단/관리 작업인지 확인하고 비인가 스캔이면 단말 격리 및 프로세스 점검",
                Score = a.RiskScore
            });
        }
        if (!a.PolicyTrustedInternal && a.LateralMovementTargetCount >= 4)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.LateralMovementTargetCount >= 20 ? "HIGH" : a.LateralMovementTargetCount >= 8 ? "MEDIUM" : "WATCH",
                Code = "LATERAL_MOVEMENT",
                IpAddress = a.IpAddress,
                Title = "내부 횡적 이동 후보",
                Evidence = $"최근 5분 동안 SMB/RDP/WinRM/SSH 등 관리 포트로 서로 다른 내부 장비 {a.LateralMovementTargetCount}대 접근",
                Recommendation = "승인된 관리 서버/배포 도구인지 확인하고 비인가 단말이면 계정 사용 흔적과 원격접속 로그를 우선 점검",
                Score = a.RiskScore
            });
        }
        if (a.BeaconCandidateCount > 0)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.BeaconConfidenceScore >= 80 ? "MEDIUM" : "WATCH",
                Code = "BEACONING",
                IpAddress = a.IpAddress,
                Title = "주기적 Beaconing 후보",
                Evidence = $"{a.BeaconExternalIp}:{a.BeaconDestinationPort?.ToString() ?? "-"} 대상으로 약 {a.BeaconIntervalSeconds:0.0}초 주기, jitter {a.BeaconJitterPercent:0.0}%, confidence {a.BeaconConfidenceScore}/100",
                Recommendation = "정상 에이전트/업데이트/모니터링 heartbeat 여부를 확인하고 미승인 프로세스라면 EDR/방화벽/DNS 로그와 대조",
                Score = a.RiskScore
            });
        }
        if (a.BaselineReady && a.BaselineAnomalyScore >= 30)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.BaselineAnomalyScore >= 55 ? "MEDIUM" : "WATCH",
                Code = "BASELINE_DEVIATION",
                IpAddress = a.IpAddress,
                Title = "정상 행동 Baseline 이탈",
                Evidence = $"{a.BaselineScopeText} 학습값 대비 편차 {a.BaselineAnomalyScore}/100 · {string.Join(" · ", a.BaselineReasons.Take(3))}",
                Recommendation = "업무시간/업데이트/대량 전송 등 정상 변경 여부를 확인하고 같은 시간대의 과거 패턴과 비교",
                Score = a.RiskScore
            });
        }
        if (a.DnsAnomalyScore >= 30)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.DnsAnomalyScore >= 60 ? "MEDIUM" : "WATCH",
                Code = "DNS_ANOMALY",
                IpAddress = a.IpAddress,
                Title = "DNS 이상 패턴 후보",
                Evidence = $"최근 5분 DNS {a.DnsQueryCount5m}건 · 고유 {a.DnsUniqueQueryCount5m}건 · NXDOMAIN {a.DnsNxDomainCount5m}건 ({a.DnsNxDomainRatioPercent:0.0}%) · 긴 질의 {a.DnsLongQueryCount5m}건 / 최대 {a.DnsMaxQueryLength}자",
                Recommendation = "DGA/터널링/오입력 가능성을 구분하기 위해 질의 도메인, 실행 프로세스, DNS 서버 로그를 대조하고 정상 도메인은 정책에 등록",
                Score = a.RiskScore
            });
        }
        if (a.ExternalIntelSuspiciousCount > 0 || a.ExternalIntelWatchCount > 0)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.ExternalIntelSuspiciousCount > 0 ? "MEDIUM" : "WATCH",
                Code = "EXTERNAL_INTELLIGENCE",
                IpAddress = a.IpAddress,
                Title = "외부 목적지 로컬 인텔리전스 일치",
                Evidence = $"분석가 제공 CIDR 인텔리전스 기준 SUSPICIOUS {a.ExternalIntelSuspiciousCount}개 · WATCH {a.ExternalIntelWatchCount}개",
                Recommendation = "CSV 인텔리전스의 출처/최종 갱신 시점을 확인한 뒤 해당 외부 목적지와 프로세스/방화벽/DNS 로그를 교차 검증",
                Score = a.RiskScore
            });
        }
        if (a.UnapprovedExternalFanOutCount >= 15)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.RiskScore >= 50 ? "MEDIUM" : a.RiskScore >= 25 ? "WATCH" : "INFO",
                Code = "EXTERNAL_FANOUT",
                IpAddress = a.IpAddress,
                Title = "미승인 외부 Connection Fan-out 증가",
                Evidence = $"최근 5분 TCP SYN 기준 미승인 외부 목적지 {a.UnapprovedExternalFanOutCount}개 · 전체 {a.FanOutExternalCount}개 · 정책 제외 {a.PolicyAllowedExternalCount}개",
                Recommendation = "브라우저/업데이트/CDN 등 정상 원인은 보안 정책 Allowlist로 관리하고, 남은 목적지의 Baseline 대비 급증 여부를 비교",
                Score = a.RiskScore
            });
        }
        if (a.RecentNewExternalCount >= 15)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.RiskScore >= 25 ? "WATCH" : "INFO",
                Code = "NEW_EXTERNAL",
                IpAddress = a.IpAddress,
                Title = "신규 외부 목적지 다수 관찰",
                Evidence = $"현재 분석 세션에서 최근 10분 신규 외부 목적지 {a.RecentNewExternalCount}개",
                Recommendation = "업데이트/클라우드 서비스 등 정상 변경인지 확인하고 미승인 외부 목적지를 선별",
                Score = a.RiskScore
            });
        }
        if (a.LongLivedFlowCount > 0)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.RiskScore >= 25 ? "WATCH" : "INFO",
                Code = "LONG_LIVED",
                IpAddress = a.IpAddress,
                Title = "장시간 지속/반복 외부 흐름",
                Evidence = $"15분 이상 지속되며 최근에도 관찰되는 외부 흐름 {a.LongLivedFlowCount}개",
                Recommendation = "업무용 상시 세션인지 확인하고 비업무 목적의 장기 외부 연결은 프로세스/방화벽 로그와 대조",
                Score = a.RiskScore
            });
        }
        if (a.SuspiciousExternalPortCount > 0)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.RiskScore >= 50 ? "MEDIUM" : "WATCH",
                Code = "ATTENTION_PORT",
                IpAddress = a.IpAddress,
                Title = "외부 주의 포트 통신 관찰",
                Evidence = $"원격관리/파일공유/DB 등 주의 서비스 포트 {a.SuspiciousExternalPortCount}종 관찰",
                Recommendation = "외부 통신 필요성을 검증하고 방화벽 정책/프로세스 소유자/원격관리 사용 여부를 확인",
                Score = a.RiskScore
            });
        }
        if (a.ExternalBytes5m >= 10L * 1024 * 1024 && a.UploadRatioPercent >= 92)
        {
            findings.Add(new SecurityRelationshipFinding
            {
                Severity = a.ExternalBytes5m >= 50L * 1024 * 1024 ? "WATCH" : "INFO",
                Code = "OUTBOUND_HEAVY",
                IpAddress = a.IpAddress,
                Title = "외부 송신 편중 관찰",
                Evidence = $"최근 5분 외부 데이터 {TrafficAuditFlowRecord.FormatBytes(a.ExternalBytes5m)} 중 송신 비율 {a.UploadRatioPercent:0.0}%",
                Recommendation = "백업/동기화/업로드 업무인지 확인하고 예상하지 못한 대량 송신이면 프로세스와 목적지 도메인을 확인",
                Score = a.RiskScore
            });
        }
    }

    private bool IsExternalAllowedPeer(string externalIp, int? port)
    {
        if (string.IsNullOrWhiteSpace(externalIp)) return false;
        _externalObservedHosts.TryGetValue(externalIp, out string? host);
        string serviceGroup = ExternalServiceClassifier.ClassifyHost(host);
        return _policy.IsExternalAllowed(externalIp, host, serviceGroup, port);
    }

    private bool IsFlowPolicyAllowed(FlowAccumulator flow)
    {
        string externalIp;
        int? port;
        if (IsPublicIpv4(flow.DestinationIp))
        {
            externalIp = flow.DestinationIp;
            port = flow.DestinationPort;
        }
        else if (IsPublicIpv4(flow.SourceIp))
        {
            externalIp = flow.SourceIp;
            port = flow.SourcePort;
        }
        else return false;
        return IsExternalAllowedPeer(externalIp, port);
    }

    private static bool IsExternalFlow(FlowAccumulator flow) =>
        (IsPrivateIpv4(flow.SourceIp) && IsPublicIpv4(flow.DestinationIp)) ||
        (IsPublicIpv4(flow.SourceIp) && IsPrivateIpv4(flow.DestinationIp));

    private static bool IsLongLivedFlow(FlowAccumulator flow, DateTime now)
    {
        if ((flow.LastSeenUtc - flow.FirstSeenUtc) < TimeSpan.FromMinutes(15)) return false;
        if ((now - flow.LastSeenUtc) > TimeSpan.FromMinutes(2)) return false;
        if (string.Equals(flow.Protocol, "TCP", StringComparison.OrdinalIgnoreCase))
            return flow.ConnectionStarts == 0 || flow.ConnectionStarts > flow.ConnectionEnds;
        return true;
    }

    private static string FlowKey(string sourceIp, string destinationIp, string protocol, int? destinationPort) =>
        $"{sourceIp}|{destinationIp}|{protocol}|{destinationPort?.ToString() ?? ""}";

    private static double Median(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return 0;
        var sorted = values.OrderBy(v => v).ToArray();
        int mid = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[mid - 1] + sorted[mid]) / 2.0 : sorted[mid];
    }

    private static bool IsAttentionPort(int? port) => port.HasValue && AttentionExternalPorts.Contains(port.Value);
    private static bool IsInternalManagementPort(int? port) => port.HasValue && InternalManagementPorts.Contains(port.Value);

    private static string ToRiskLevel(int score) => score switch
    {
        >= 75 => "HIGH",
        >= 50 => "MEDIUM",
        >= 25 => "WATCH",
        _ => "NORMAL"
    };

    private static int SeverityOrder(string severity) => severity.ToUpperInvariant() switch
    {
        "HIGH" => 4,
        "MEDIUM" => 3,
        "WATCH" => 2,
        _ => 1
    };

    private static bool IsPrivateIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var ip)) return false;
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return false;
        if (b[0] == 10) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        return false;
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
