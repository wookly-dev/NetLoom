using System.Net;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

/// <summary>
/// Separates packet collection from topology rendering. All packet/flow metadata remains available
/// to Packet Inspector, audit and security analysis, while 2D/3D topology renders only relationships
/// that carry operational or security significance. This prevents the sensor host's ordinary SaaS/CDN
/// traffic from visually dominating other internal devices.
/// </summary>
public static class TopologySignificanceService
{
    private sealed class PeerStats
    {
        public string InternalIp = "";
        public string ExternalIp = "";
        public long Packets;
        public long Bytes;
        public DateTime FirstSeenUtc = DateTime.MaxValue;
        public DateTime LastSeenUtc = DateTime.MinValue;
        public int Score;
        public bool ForceVisible;
        public bool SecurityMatched;
        public bool BeaconMatched;
        public bool AttentionPort;
        public bool KnownService;
        public string Reason = "";
    }

    private sealed class NodeCandidate
    {
        public ExternalObservationNodeRecord Node = new();
        public readonly Dictionary<string, PeerStats> Peers = new(StringComparer.OrdinalIgnoreCase);
        public int Score;
        public bool ForceVisible;
        public string PrimaryPeerIp = "";
        public string Reason = "";
    }

    public static TopologySignificanceSnapshot Build(
        ExternalObservationSnapshot external,
        SecurityRelationshipSnapshot security,
        CaptureCoverageSnapshot coverage,
        bool includeLowSignificance = false,
        bool excludeSensorHostConnections = false)
    {
        external ??= ExternalObservationSnapshot.Empty;
        security ??= SecurityRelationshipSnapshot.Empty;
        coverage ??= CaptureCoverageSnapshot.Empty;

        int observedNodes = external.Nodes.Count(n => IsPublicIpv4(n.IpAddress));
        int observedFlows = external.Flows.Count(f => IsExternalPeerFlow(f, out _, out _));
        string sensorAddress = coverage.AdapterAddress?.Trim() ?? string.Empty;
        int sensorHostObservedFlows = 0;
        var sensorHostExternalIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (excludeSensorHostConnections && !string.IsNullOrWhiteSpace(sensorAddress))
        {
            foreach (var flow in external.Flows)
            {
                if (!IsExternalPeerFlow(flow, out string internalIp, out string externalIp)) continue;
                if (!string.Equals(internalIp, sensorAddress, StringComparison.OrdinalIgnoreCase)) continue;
                sensorHostObservedFlows++;
                sensorHostExternalIps.Add(externalIp);
            }
        }

        if (!coverage.CanRenderObservedExternalTopology || observedNodes == 0)
        {
            return new TopologySignificanceSnapshot
            {
                ObservedNodeCount = observedNodes,
                SuppressedNodeCount = observedNodes,
                ObservedFlowCount = observedFlows,
                SuppressedFlowCount = observedFlows,
                SensorHostConnectionsExcluded = excludeSensorHostConnections,
                SensorHostSuppressedNodeCount = excludeSensorHostConnections ? sensorHostExternalIps.Count : 0,
                SensorHostSuppressedFlowCount = excludeSensorHostConnections ? sensorHostObservedFlows : 0,
                Signature = coverage.CanRenderObservedExternalTopology ? $"EMPTY-X{(excludeSensorHostConnections ? 1 : 0)}" : $"HIDDEN-X{(excludeSensorHostConnections ? 1 : 0)}"
            };
        }

        var nodeByIp = external.Nodes
            .Where(n => IsPublicIpv4(n.IpAddress))
            .GroupBy(n => n.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.LastSeenUtc).First(), StringComparer.OrdinalIgnoreCase);

        var candidates = nodeByIp.ToDictionary(
            pair => pair.Key,
            pair => new NodeCandidate { Node = pair.Value },
            StringComparer.OrdinalIgnoreCase);

        foreach (var flow in external.Flows)
        {
            if (!IsExternalPeerFlow(flow, out string internalIp, out string externalIp)) continue;
            if (!candidates.TryGetValue(externalIp, out var candidate)) continue;

            if (!candidate.Peers.TryGetValue(internalIp, out var peer))
            {
                peer = new PeerStats { InternalIp = internalIp, ExternalIp = externalIp };
                candidate.Peers[internalIp] = peer;
            }

            peer.Packets += flow.Packets;
            peer.Bytes += flow.Bytes;
            if (flow.FirstSeenUtc != default && flow.FirstSeenUtc < peer.FirstSeenUtc) peer.FirstSeenUtc = flow.FirstSeenUtc;
            if (flow.LastSeenUtc > peer.LastSeenUtc) peer.LastSeenUtc = flow.LastSeenUtc;
            int? servicePort = ExternalServicePort(flow, externalIp);
            if (IsAttentionPort(servicePort)) peer.AttentionPort = true;
        }

        var suspiciousPairRisk = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var flow in security.SuspiciousFlows.Where(f => f.IsExternal))
        {
            if (!TryInternalExternal(flow.SourceIp, flow.DestinationIp, out string internalIp, out string externalIp)) continue;
            string key = PairKey(internalIp, externalIp);
            suspiciousPairRisk[key] = Math.Max(suspiciousPairRisk.TryGetValue(key, out int prior) ? prior : 0, flow.RiskScore);
        }

        var beaconPairs = security.BeaconCandidates
            .Where(b => IsPublicIpv4(b.ExternalIp) && !string.IsNullOrWhiteSpace(b.InternalIp))
            .Select(b => PairKey(b.InternalIp, b.ExternalIp))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var securityNodeByIp = security.Nodes
            .GroupBy(n => n.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        // Some nodes outlive the compact flow list. Recreate one conservative pseudo-peer before
        // applying the visualization-only sensor-host exclusion so local-only endpoints can be
        // removed consistently without touching the raw observation/security stores.
        foreach (var candidate in candidates.Values)
        {
            if (candidate.Peers.Count == 0 && !string.IsNullOrWhiteSpace(candidate.Node.LastPeerIp) && !IsPublicIpv4(candidate.Node.LastPeerIp))
            {
                candidate.Peers[candidate.Node.LastPeerIp] = new PeerStats
                {
                    InternalIp = candidate.Node.LastPeerIp,
                    ExternalIp = candidate.Node.IpAddress,
                    Packets = candidate.Node.Packets,
                    Bytes = candidate.Node.Bytes,
                    FirstSeenUtc = candidate.Node.FirstSeenUtc,
                    LastSeenUtc = candidate.Node.LastSeenUtc,
                    AttentionPort = IsAttentionPort(candidate.Node.LastPort)
                };
            }
        }

        int sensorHostSuppressedNodes = 0;
        if (excludeSensorHostConnections && !string.IsNullOrWhiteSpace(sensorAddress))
        {
            foreach (var candidate in candidates.Values)
            {
                bool removed = candidate.Peers.Remove(sensorAddress);
                if (removed && candidate.Peers.Count == 0)
                    sensorHostSuppressedNodes++;
            }
        }

        var renderCandidates = candidates.Values.Where(c => c.Peers.Count > 0).ToArray();
        foreach (var candidate in renderCandidates)
        {
            bool intelSuspicious = string.Equals(candidate.Node.IntelligenceClassification, "SUSPICIOUS", StringComparison.OrdinalIgnoreCase);
            bool intelWatch = string.Equals(candidate.Node.IntelligenceClassification, "WATCH", StringComparison.OrdinalIgnoreCase);
            bool knownService = IsKnownInfrastructureService(candidate.Node.ServiceGroup);

            foreach (var peer in candidate.Peers.Values)
            {
                peer.KnownService = knownService;
                var reasons = new List<string>();
                int score = 0;

                string pairKey = PairKey(peer.InternalIp, candidate.Node.IpAddress);
                int pairRisk = suspiciousPairRisk.TryGetValue(pairKey, out int risk) ? risk : 0;
                if (pairRisk >= 15)
                {
                    peer.SecurityMatched = true;
                    peer.ForceVisible = true;
                    score += 75 + Math.Min(20, pairRisk / 4);
                    reasons.Add($"보안 Flow {pairRisk}");
                }

                if (beaconPairs.Contains(pairKey) ||
                    (securityNodeByIp.TryGetValue(peer.InternalIp, out var assessment) &&
                     assessment.BeaconCandidateCount > 0 &&
                     string.Equals(assessment.BeaconExternalIp, candidate.Node.IpAddress, StringComparison.OrdinalIgnoreCase)))
                {
                    peer.BeaconMatched = true;
                    peer.ForceVisible = true;
                    score += 95;
                    reasons.Add("Beacon 후보");
                }

                if (intelSuspicious)
                {
                    peer.ForceVisible = true;
                    score += 95;
                    reasons.Add("Intelligence SUSPICIOUS");
                }
                else if (intelWatch)
                {
                    peer.ForceVisible = true;
                    score += 65;
                    reasons.Add("Intelligence WATCH");
                }

                if (peer.AttentionPort)
                {
                    score += 35;
                    reasons.Add("주의 포트");
                }

                score += VolumeScore(peer.Bytes, peer.Packets);

                var duration = peer.LastSeenUtc > peer.FirstSeenUtc && peer.FirstSeenUtc != DateTime.MaxValue
                    ? peer.LastSeenUtc - peer.FirstSeenUtc
                    : TimeSpan.Zero;
                if (duration >= TimeSpan.FromMinutes(15)) { score += 22; reasons.Add("15분+ 반복/지속"); }
                else if (duration >= TimeSpan.FromMinutes(5)) { score += 14; reasons.Add("5분+ 반복"); }
                else if (duration >= TimeSpan.FromMinutes(1)) score += 7;

                if (peer.Packets >= 20) reasons.Add($"{peer.Packets:N0} pkt");
                if (peer.Bytes >= 64 * 1024) reasons.Add(TrafficAuditFlowRecord.FormatBytes(peer.Bytes));

                if (knownService && !peer.ForceVisible)
                {
                    score -= peer.Bytes < 512 * 1024 && peer.Packets < 30 ? 16 : 7;
                }
                else if (string.Equals(candidate.Node.ServiceGroup, "Unknown", StringComparison.OrdinalIgnoreCase) && !peer.ForceVisible)
                {
                    score += 5;
                }

                // The NetLoom sensor host is naturally much noisier than the rest of the network.
                // Use a stronger display threshold for that host, but never suppress security-forced edges.
                if (!peer.ForceVisible && !string.IsNullOrWhiteSpace(coverage.AdapterAddress) &&
                    string.Equals(peer.InternalIp, coverage.AdapterAddress, StringComparison.OrdinalIgnoreCase))
                {
                    score -= coverage.Mode == PacketCaptureScopeMode.SpanTap ? 13 : 22;
                    reasons.Add("센서 호스트 노이즈 억제");
                }

                peer.Score = Math.Clamp(score, 0, 200);
                peer.Reason = string.Join(" · ", reasons.Distinct(StringComparer.OrdinalIgnoreCase).Take(5));
            }

            int peerCount = candidate.Peers.Count;
            if (peerCount >= 4) candidate.Score += 26;
            else if (peerCount >= 2) candidate.Score += 15;

            var strongest = candidate.Peers.Values
                .OrderByDescending(p => p.ForceVisible)
                .ThenByDescending(p => p.Score)
                .ThenByDescending(p => p.Bytes)
                .FirstOrDefault();
            if (strongest is not null)
            {
                candidate.Score += strongest.Score;
                candidate.ForceVisible = strongest.ForceVisible;
                candidate.PrimaryPeerIp = strongest.InternalIp;
                candidate.Reason = strongest.Reason;
            }
            candidate.Score = Math.Clamp(candidate.Score, 0, 220);
        }

        var selectedIps = includeLowSignificance
            ? renderCandidates.Select(c => c.Node.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : SelectSignificantNodes(renderCandidates, coverage);

        var selectedDecisions = renderCandidates
            .Where(c => selectedIps.Contains(c.Node.IpAddress))
            .OrderByDescending(c => c.ForceVisible)
            .ThenByDescending(c => c.Score)
            .ThenByDescending(c => excludeSensorHostConnections ? c.Peers.Values.Sum(p => p.Bytes) : c.Node.Bytes)
            .Select(c => new TopologyExternalNodeDecision
            {
                Node = BuildRenderedNode(c, excludeSensorHostConnections),
                Score = c.Score,
                ForceVisible = c.ForceVisible,
                InternalPeerCount = c.Peers.Count,
                PrimaryPeerIp = c.PrimaryPeerIp,
                Reason = string.IsNullOrWhiteSpace(c.Reason)
                    ? (c.Peers.Count > 1 ? $"내부 {c.Peers.Count:N0}대 공통 목적지" : "반복/트래픽 기준")
                    : c.Reason
            })
            .ToArray();

        var selectedFlows = AggregateSelectedFlows(
                external.Flows,
                selectedIps,
                candidates,
                coverage,
                includeLowSignificance,
                excludeSensorHostConnections)
            .OrderByDescending(f => PairIsSecurityForced(f, candidates))
            .ThenByDescending(f => f.Bytes)
            .ThenByDescending(f => f.Packets)
            .Take(160)
            .ToArray();

        string serviceSummary = string.Join(" · ", selectedDecisions
            .GroupBy(n => string.IsNullOrWhiteSpace(n.Node.ServiceGroup) ? "Unknown" : n.Node.ServiceGroup, StringComparer.CurrentCultureIgnoreCase)
            .OrderBy(g => string.Equals(g.Key, "Unknown", StringComparison.OrdinalIgnoreCase) ? 1 : 0)
            .ThenByDescending(g => g.Sum(x => x.Node.Bytes))
            .Take(4)
            .Select(g => $"{g.Key} {g.Count():N0}"));

        string nodeSignature = string.Join("|", selectedDecisions
            .OrderBy(x => x.Node.IpAddress, StringComparer.OrdinalIgnoreCase)
            .Select(x =>
            {
                int scoreBucket = Math.Min(200, (x.Score / 20) * 20);
                int peerBucket = Math.Min(4, x.InternalPeerCount);
                return $"{x.Node.IpAddress}~{x.Node.ServiceGroup}~{x.Node.ObservedHost}~{x.Node.IntelligenceClassification}~{(x.ForceVisible ? 1 : 0)}~S{scoreBucket}~P{peerBucket}";
            }));
        string flowSignature = string.Join("|", selectedFlows
            .Select(f => TryInternalExternal(f.SourceIp, f.DestinationIp, out string internalIp, out string externalIp)
                ? $"{internalIp}>{externalIp}"
                : $"{f.SourceIp}>{f.DestinationIp}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
        string signature = $"X:{(excludeSensorHostConnections ? 1 : 0)}||N:{nodeSignature}||F:{flowSignature}";

        return new TopologySignificanceSnapshot
        {
            ExternalNodes = selectedDecisions,
            ExternalFlows = selectedFlows,
            ObservedNodeCount = observedNodes,
            RenderedNodeCount = selectedDecisions.Length,
            SuppressedNodeCount = Math.Max(0, observedNodes - selectedDecisions.Length),
            ObservedFlowCount = observedFlows,
            RenderedFlowCount = selectedFlows.Length,
            SuppressedFlowCount = Math.Max(0, observedFlows - selectedFlows.Length),
            SensorHostConnectionsExcluded = excludeSensorHostConnections,
            SensorHostSuppressedNodeCount = excludeSensorHostConnections ? sensorHostSuppressedNodes : 0,
            SensorHostSuppressedFlowCount = excludeSensorHostConnections ? sensorHostObservedFlows : 0,
            ServiceSummaryText = serviceSummary,
            Signature = signature
        };
    }

    private static ExternalObservationNodeRecord BuildRenderedNode(NodeCandidate candidate, bool excludeSensorHostConnections)
    {
        if (!excludeSensorHostConnections) return candidate.Node;

        var peers = candidate.Peers.Values.ToArray();
        if (peers.Length == 0) return candidate.Node;
        DateTime firstSeen = peers.Where(p => p.FirstSeenUtc != DateTime.MaxValue).Select(p => p.FirstSeenUtc).DefaultIfEmpty(candidate.Node.FirstSeenUtc).Min();
        DateTime lastSeen = peers.Where(p => p.LastSeenUtc != DateTime.MinValue).Select(p => p.LastSeenUtc).DefaultIfEmpty(candidate.Node.LastSeenUtc).Max();
        var primary = peers.OrderByDescending(p => p.ForceVisible).ThenByDescending(p => p.Score).ThenByDescending(p => p.Bytes).First();

        // When the sensor-host edge is hidden, expose only the traffic volume represented by the
        // remaining visible peers. This prevents a shared External node from still looking huge
        // merely because the NetLoom PC contributed most of its bytes. Classification metadata is
        // retained from the observation node; raw observation/security data remains untouched.
        return new ExternalObservationNodeRecord
        {
            IpAddress = candidate.Node.IpAddress,
            FirstSeenUtc = firstSeen,
            LastSeenUtc = lastSeen,
            Packets = peers.Sum(p => p.Packets),
            Bytes = peers.Sum(p => p.Bytes),
            LastPeerIp = primary.InternalIp,
            LastProtocol = candidate.Node.LastProtocol,
            LastPort = candidate.Node.LastPort,
            ObservedHost = candidate.Node.ObservedHost,
            ServiceGroup = candidate.Node.ServiceGroup,
            Country = candidate.Node.Country,
            Asn = candidate.Node.Asn,
            Provider = candidate.Node.Provider,
            IntelligenceClassification = candidate.Node.IntelligenceClassification
        };
    }

    private static HashSet<string> SelectSignificantNodes(IEnumerable<NodeCandidate> source, CaptureCoverageSnapshot coverage)
    {
        var candidates = source.ToList();
        var selected = candidates.Where(c => c.ForceVisible)
            .Select(c => c.Node.IpAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var peers = candidates
            .SelectMany(c => c.Peers.Values.Select(p => (Candidate: c, Peer: p)))
            .GroupBy(x => x.Peer.InternalIp, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => string.Equals(g.Key, coverage.AdapterAddress, StringComparison.OrdinalIgnoreCase) ? 1 : 0)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        int topPerPeer = coverage.Mode == PacketCaptureScopeMode.LocalHost ? 5 : 8;
        int globalMax = coverage.Mode == PacketCaptureScopeMode.LocalHost ? 12 : 72;

        // Fair round-robin selection. A very chatty sensor/workstation cannot consume every slot
        // before quieter internal devices receive representation in the relationship map.
        var rankedByPeer = peers.ToDictionary(
            g => g.Key,
            g => g.OrderByDescending(x => x.Peer.ForceVisible)
                  .ThenByDescending(x => x.Peer.Score)
                  .ThenByDescending(x => x.Peer.Bytes)
                  .ToArray(),
            StringComparer.OrdinalIgnoreCase);

        for (int rank = 0; rank < topPerPeer && selected.Count < globalMax; rank++)
        {
            foreach (var peerGroup in peers)
            {
                if (selected.Count >= globalMax) break;
                var ranked = rankedByPeer[peerGroup.Key];
                if (rank >= ranked.Length) continue;
                var item = ranked[rank];
                if (selected.Contains(item.Candidate.Node.IpAddress)) continue;

                bool sensorHost = !string.IsNullOrWhiteSpace(coverage.AdapterAddress) &&
                                  string.Equals(peerGroup.Key, coverage.AdapterAddress, StringComparison.OrdinalIgnoreCase);
                int threshold = sensorHost ? 38 : 20;
                if (item.Peer.ForceVisible || item.Peer.Score >= threshold)
                    selected.Add(item.Candidate.Node.IpAddress);
            }
        }

        // Keep shared/common destinations visible because they explain cross-device behavior even
        // when each individual flow is only moderate.
        foreach (var candidate in candidates
                     .Where(c => c.Peers.Count >= 2 && c.Score >= 24)
                     .OrderByDescending(c => c.Peers.Count)
                     .ThenByDescending(c => c.Score))
        {
            if (selected.Count >= globalMax) break;
            selected.Add(candidate.Node.IpAddress);
        }

        return selected;
    }

    private static IEnumerable<ExternalObservationFlowRecord> AggregateSelectedFlows(
        IReadOnlyList<ExternalObservationFlowRecord> flows,
        IReadOnlySet<string> selectedIps,
        IReadOnlyDictionary<string, NodeCandidate> candidates,
        CaptureCoverageSnapshot coverage,
        bool includeLowSignificance,
        bool excludeSensorHostConnections)
    {
        var eligible = new List<(ExternalObservationFlowRecord Flow, string InternalIp, string ExternalIp)>();
        foreach (var flow in flows)
        {
            if (!IsExternalPeerFlow(flow, out string internalIp, out string externalIp)) continue;
            if (!selectedIps.Contains(externalIp)) continue;
            if (excludeSensorHostConnections && !string.IsNullOrWhiteSpace(coverage.AdapterAddress) &&
                string.Equals(internalIp, coverage.AdapterAddress, StringComparison.OrdinalIgnoreCase))
                continue;
            eligible.Add((flow, internalIp, externalIp));
        }

        var pairGroups = eligible.GroupBy(
            x => $"{x.InternalIp}|{x.ExternalIp}",
            StringComparer.OrdinalIgnoreCase);

        foreach (var group in pairGroups)
        {
            var list = group.Select(x => x.Flow).ToList();
            var first = list.OrderBy(f => f.FirstSeenUtc).First();
            string externalIp = IsPublicIpv4(first.SourceIp) ? first.SourceIp : first.DestinationIp;
            string internalIp = IsPublicIpv4(first.SourceIp) ? first.DestinationIp : first.SourceIp;

            if (!includeLowSignificance && candidates.TryGetValue(externalIp, out var candidate) &&
                candidate.Peers.TryGetValue(internalIp, out var peer))
            {
                bool sensorHost = !string.IsNullOrWhiteSpace(coverage.AdapterAddress) &&
                                  string.Equals(internalIp, coverage.AdapterAddress, StringComparison.OrdinalIgnoreCase);
                int threshold = sensorHost ? 34 : 16;
                if (!peer.ForceVisible && peer.Score < threshold) continue;
            }

            var representative = list.OrderByDescending(f => f.Bytes).ThenByDescending(f => f.Packets).First();
            yield return new ExternalObservationFlowRecord
            {
                FirstSeenUtc = list.Min(f => f.FirstSeenUtc),
                LastSeenUtc = list.Max(f => f.LastSeenUtc),
                SourceIp = representative.SourceIp,
                DestinationIp = representative.DestinationIp,
                Protocol = representative.Protocol,
                SourcePort = representative.SourcePort,
                DestinationPort = representative.DestinationPort,
                Packets = list.Sum(f => f.Packets),
                Bytes = list.Sum(f => f.Bytes)
            };
        }
    }

    private static bool PairIsSecurityForced(ExternalObservationFlowRecord flow, IReadOnlyDictionary<string, NodeCandidate> candidates)
    {
        if (!IsExternalPeerFlow(flow, out string internalIp, out string externalIp)) return false;
        return candidates.TryGetValue(externalIp, out var candidate) &&
               candidate.Peers.TryGetValue(internalIp, out var peer) && peer.ForceVisible;
    }

    private static int VolumeScore(long bytes, long packets)
    {
        int score = bytes switch
        {
            >= 50L * 1024 * 1024 => 45,
            >= 5L * 1024 * 1024 => 36,
            >= 512L * 1024 => 27,
            >= 64L * 1024 => 18,
            >= 8L * 1024 => 9,
            _ => 0
        };
        score += packets switch
        {
            >= 500 => 30,
            >= 100 => 22,
            >= 25 => 14,
            >= 8 => 7,
            _ => 0
        };
        return score;
    }

    private static bool IsKnownInfrastructureService(string serviceGroup)
    {
        if (string.IsNullOrWhiteSpace(serviceGroup)) return false;
        return serviceGroup.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Google", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("AWS", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Cloudflare", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Apple", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Meta", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Naver", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("Kakao", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Equals("GitHub", StringComparison.OrdinalIgnoreCase) ||
               serviceGroup.Contains("CDN", StringComparison.OrdinalIgnoreCase);
    }

    private static int? ExternalServicePort(ExternalObservationFlowRecord flow, string externalIp)
    {
        return string.Equals(flow.DestinationIp, externalIp, StringComparison.OrdinalIgnoreCase)
            ? flow.DestinationPort ?? flow.SourcePort
            : flow.SourcePort ?? flow.DestinationPort;
    }

    private static bool IsAttentionPort(int? port) => port is
        21 or 22 or 23 or 25 or 110 or 135 or 137 or 138 or 139 or 445 or 1433 or 1521 or 2049 or 2375 or 2376 or 3306 or 3389 or 5432 or 5900 or 5985 or 5986 or 6379 or 8080 or 8443 or 9200 or 11211 or 27017;

    private static bool IsExternalPeerFlow(ExternalObservationFlowRecord flow, out string internalIp, out string externalIp)
        => TryInternalExternal(flow.SourceIp, flow.DestinationIp, out internalIp, out externalIp);

    private static bool TryInternalExternal(string sourceIp, string destinationIp, out string internalIp, out string externalIp)
    {
        bool sourceExternal = IsPublicIpv4(sourceIp);
        bool destinationExternal = IsPublicIpv4(destinationIp);
        if (sourceExternal == destinationExternal)
        {
            internalIp = "";
            externalIp = "";
            return false;
        }

        externalIp = sourceExternal ? sourceIp : destinationIp;
        internalIp = sourceExternal ? destinationIp : sourceIp;
        return !string.IsNullOrWhiteSpace(internalIp);
    }

    private static string PairKey(string internalIp, string externalIp) => $"{internalIp}|{externalIp}";

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
