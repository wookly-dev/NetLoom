using System.Net;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

/// <summary>
/// Keeps public/external IPs observed by the local packet capture until the user explicitly
/// clears them. This is intentionally independent from the short-lived LIVE traffic snapshot.
/// Only metadata is retained; packet payload is never stored here.
/// </summary>
public sealed class ExternalObservationRegistry
{
    private sealed class NodeAccumulator
    {
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public long Packets;
        public long Bytes;
        public string LastPeerIp = "";
        public string LastProtocol = "IP";
        public int? LastPort;
        public string ObservedHost = "";
        public string ServiceGroup = "Unknown";
        public string Country = "";
        public string Asn = "";
        public string Provider = "";
        public string IntelligenceClassification = "UNKNOWN";
    }

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
    }

    private readonly object _sync = new();
    private readonly ExternalIntelligenceService _intelligence;
    private readonly Dictionary<string, NodeAccumulator> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FlowAccumulator> _flows = new(StringComparer.OrdinalIgnoreCase);
    private long _nodeSetVersion;

    public ExternalObservationRegistry(ExternalIntelligenceService? intelligence = null)
    {
        _intelligence = intelligence ?? new ExternalIntelligenceService();
    }

    public int Count
    {
        get { lock (_sync) return _nodes.Count; }
    }

    public void Add(PacketObservation packet)
    {
        if (packet.Length <= 0 || string.IsNullOrWhiteSpace(packet.SourceIp) || string.IsNullOrWhiteSpace(packet.DestinationIp))
            return;

        bool sourceExternal = IsPublicIpv4(packet.SourceIp);
        bool destinationExternal = IsPublicIpv4(packet.DestinationIp);
        if (!sourceExternal && !destinationExternal) return;

        lock (_sync)
        {
            string observedHost = ExternalServiceClassifier.ExtractObservedHost(packet.ApplicationSummary);
            if (sourceExternal)
                AddNode(packet.SourceIp, packet.DestinationIp, packet.Protocol, packet.SourcePort ?? packet.DestinationPort, packet.Timestamp, packet.Length, "");
            if (destinationExternal)
                AddNode(packet.DestinationIp, packet.SourceIp, packet.Protocol, packet.DestinationPort ?? packet.SourcePort, packet.Timestamp, packet.Length, observedHost);

            // Retain a compact external communication relationship so a stopped LIVE flow can
            // still be understood on the 2D/3D topology. Direction remains exactly as observed.
            string key = $"{packet.SourceIp}|{packet.DestinationIp}|{packet.Protocol}|{packet.DestinationPort?.ToString() ?? ""}";
            if (!_flows.TryGetValue(key, out var flow))
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
                _flows[key] = flow;
            }
            flow.LastSeenUtc = packet.Timestamp;
            flow.SourcePort = packet.SourcePort;
            flow.Packets++;
            flow.Bytes += packet.Length;

            // Safety bounds for very long captures. Normal office audits stay far below these.
            if (_nodes.Count > 4096)
            {
                foreach (var oldIp in _nodes.OrderBy(kv => kv.Value.LastSeenUtc).Take(_nodes.Count - 3072).Select(kv => kv.Key).ToArray())
                    _nodes.Remove(oldIp);
                _nodeSetVersion++;
            }
            if (_flows.Count > 16384)
            {
                foreach (var oldKey in _flows.OrderBy(kv => kv.Value.LastSeenUtc).Take(_flows.Count - 12288).Select(kv => kv.Key).ToArray())
                    _flows.Remove(oldKey);
            }
        }
    }

    public void Clear()
    {
        lock (_sync)
        {
            _nodes.Clear();
            _flows.Clear();
            _nodeSetVersion++;
        }
    }

    public void RefreshIntelligence()
    {
        lock (_sync)
        {
            foreach (var pair in _nodes)
                ApplyIntelligence(pair.Value, pair.Key);
            _nodeSetVersion++;
        }
    }

    public ExternalObservationSnapshot TakeSnapshot(int maxNodes = 512, int maxFlows = 2048)
    {
        lock (_sync)
        {
            maxNodes = Math.Clamp(maxNodes, 1, 4096);
            maxFlows = Math.Clamp(maxFlows, 1, 16384);
            return new ExternalObservationSnapshot
            {
                NodeSetVersion = _nodeSetVersion,
                Nodes = _nodes
                    .Select(pair => new ExternalObservationNodeRecord
                    {
                        IpAddress = pair.Key,
                        FirstSeenUtc = pair.Value.FirstSeenUtc,
                        LastSeenUtc = pair.Value.LastSeenUtc,
                        Packets = pair.Value.Packets,
                        Bytes = pair.Value.Bytes,
                        LastPeerIp = pair.Value.LastPeerIp,
                        LastProtocol = pair.Value.LastProtocol,
                        LastPort = pair.Value.LastPort,
                        ObservedHost = pair.Value.ObservedHost,
                        ServiceGroup = pair.Value.ServiceGroup,
                        Country = pair.Value.Country,
                        Asn = pair.Value.Asn,
                        Provider = pair.Value.Provider,
                        IntelligenceClassification = pair.Value.IntelligenceClassification
                    })
                    .OrderBy(n => n.FirstSeenUtc)
                    .ThenBy(n => n.IpAddress, StringComparer.OrdinalIgnoreCase)
                    .Take(maxNodes)
                    .ToArray(),
                Flows = _flows.Values
                    .OrderByDescending(f => f.Bytes)
                    .ThenByDescending(f => f.Packets)
                    .Take(maxFlows)
                    .Select(f => new ExternalObservationFlowRecord
                    {
                        FirstSeenUtc = f.FirstSeenUtc,
                        LastSeenUtc = f.LastSeenUtc,
                        SourceIp = f.SourceIp,
                        DestinationIp = f.DestinationIp,
                        Protocol = f.Protocol,
                        SourcePort = f.SourcePort,
                        DestinationPort = f.DestinationPort,
                        Packets = f.Packets,
                        Bytes = f.Bytes
                    })
                    .ToArray()
            };
        }
    }

    private void AddNode(string externalIp, string peerIp, string protocol, int? port, DateTime timestamp, int length, string observedHost)
    {
        if (!_nodes.TryGetValue(externalIp, out var node))
        {
            node = new NodeAccumulator
            {
                FirstSeenUtc = timestamp,
                LastSeenUtc = timestamp
            };
            ApplyIntelligence(node, externalIp);
            _nodes[externalIp] = node;
            _nodeSetVersion++;
        }

        node.LastSeenUtc = timestamp;
        node.Packets++;
        node.Bytes += length;
        node.LastPeerIp = peerIp;
        node.LastProtocol = string.IsNullOrWhiteSpace(protocol) ? "IP" : protocol;
        node.LastPort = port;
        // Keep the first passive hostname classification for a public IP during this session.
        // A single CDN/public endpoint may serve many SNI names; changing the label on every packet
        // would churn the 3D scene and make historical grouping visually unstable.
        if (!string.IsNullOrWhiteSpace(observedHost) && string.IsNullOrWhiteSpace(node.ObservedHost))
        {
            node.ObservedHost = observedHost;
            node.ServiceGroup = ExternalServiceClassifier.ClassifyHost(observedHost);
            _nodeSetVersion++;
        }
    }

    private void ApplyIntelligence(NodeAccumulator node, string externalIp)
    {
        node.Country = "";
        node.Asn = "";
        node.Provider = "";
        node.IntelligenceClassification = "UNKNOWN";
        var intel = _intelligence.Lookup(externalIp);
        if (intel is null) return;
        node.Country = intel.Country;
        node.Asn = intel.Asn;
        node.Provider = intel.Provider;
        node.IntelligenceClassification = intel.Classification;
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
