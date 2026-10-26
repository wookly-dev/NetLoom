using NetLoom.App.Models;

namespace NetLoom.App.Services;

public sealed class TrafficAuditRecorder
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

    private sealed class NodeAccumulator
    {
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public long TxPackets;
        public long RxPackets;
        public long TxBytes;
        public long RxBytes;
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, FlowAccumulator> _flows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NodeAccumulator> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private string _sessionId = "";
    private DateTime _startedAtUtc;
    private DateTime? _endedAtUtc;
    private string _endReason = "";
    private string _adapterAddress = "";
    private string _adapterDisplay = "";
    private long _totalPackets;
    private long _totalBytes;
    private bool _isRecording;
    private string _savedPath = "";

    public bool IsRecording { get { lock (_sync) return _isRecording; } }

    public void Start(AdapterInfo adapter)
    {
        lock (_sync)
        {
            _flows.Clear();
            _nodes.Clear();
            _sessionId = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}"[..24];
            _startedAtUtc = DateTime.UtcNow;
            _endedAtUtc = null;
            _endReason = "";
            _adapterAddress = adapter.Address;
            _adapterDisplay = adapter.Display;
            _totalPackets = 0;
            _totalBytes = 0;
            _isRecording = true;
            _savedPath = "";
        }
    }

    public void Add(PacketObservation packet)
    {
        if (packet.Length <= 0 || string.IsNullOrWhiteSpace(packet.SourceIp) || string.IsNullOrWhiteSpace(packet.DestinationIp)) return;

        lock (_sync)
        {
            if (!_isRecording) return;
            _totalPackets++;
            _totalBytes += packet.Length;

            var src = GetNode(packet.SourceIp, packet.Timestamp);
            src.TxPackets++;
            src.TxBytes += packet.Length;
            src.LastSeenUtc = packet.Timestamp;

            var dst = GetNode(packet.DestinationIp, packet.Timestamp);
            dst.RxPackets++;
            dst.RxBytes += packet.Length;
            dst.LastSeenUtc = packet.Timestamp;

            // Source ephemeral ports are intentionally excluded from the key so one logical service
            // conversation does not explode into thousands of rows. Direction remains preserved.
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
            if (packet.IsTcpConnectionStart) flow.ConnectionStarts++;
            if (packet.IsTcpFin || packet.IsTcpRst) flow.ConnectionEnds++;

            // Bound memory while still retaining a substantial audit trail.
            if (_flows.Count > 20000)
            {
                foreach (var oldKey in _flows.OrderBy(kv => kv.Value.LastSeenUtc).Take(_flows.Count - 16000).Select(kv => kv.Key).ToArray())
                    _flows.Remove(oldKey);
            }
        }
    }

    public TrafficAuditSessionSnapshot Stop(string reason = "사용자 종료")
    {
        lock (_sync)
        {
            if (_isRecording)
            {
                _isRecording = false;
                _endedAtUtc = DateTime.UtcNow;
                _endReason = reason;
            }
            return SnapshotUnsafe();
        }
    }

    public TrafficAuditSessionSnapshot TakeSnapshot(int maxFlows = 20000, int maxNodes = 4096)
    {
        lock (_sync) return SnapshotUnsafe(maxFlows, maxNodes);
    }

    public void SetSavedPath(string path)
    {
        lock (_sync) _savedPath = path ?? "";
    }

    private NodeAccumulator GetNode(string ip, DateTime timestamp)
    {
        if (_nodes.TryGetValue(ip, out var node)) return node;
        node = new NodeAccumulator { FirstSeenUtc = timestamp, LastSeenUtc = timestamp };
        _nodes[ip] = node;
        return node;
    }

    private TrafficAuditSessionSnapshot SnapshotUnsafe(int maxFlows = 20000, int maxNodes = 4096)
    {
        maxFlows = Math.Clamp(maxFlows, 1, 20000);
        maxNodes = Math.Clamp(maxNodes, 1, 8192);
        if (string.IsNullOrWhiteSpace(_sessionId)) return TrafficAuditSessionSnapshot.Empty;

        return new TrafficAuditSessionSnapshot
        {
            SessionId = _sessionId,
            IsRecording = _isRecording,
            StartedAtUtc = _startedAtUtc,
            EndedAtUtc = _endedAtUtc,
            EndReason = _endReason,
            AdapterAddress = _adapterAddress,
            AdapterDisplay = _adapterDisplay,
            TotalPackets = _totalPackets,
            TotalBytes = _totalBytes,
            UniqueFlowCount = _flows.Count,
            UniqueNodeCount = _nodes.Count,
            SavedPath = _savedPath,
            Flows = _flows.Values
                .OrderByDescending(f => f.Bytes)
                .ThenByDescending(f => f.Packets)
                .Take(maxFlows)
                .Select(f => new TrafficAuditFlowRecord
                {
                    FirstSeenUtc = f.FirstSeenUtc,
                    LastSeenUtc = f.LastSeenUtc,
                    SourceIp = f.SourceIp,
                    DestinationIp = f.DestinationIp,
                    Protocol = f.Protocol,
                    SourcePort = f.SourcePort,
                    DestinationPort = f.DestinationPort,
                    Packets = f.Packets,
                    Bytes = f.Bytes,
                    ConnectionStarts = f.ConnectionStarts,
                    ConnectionEnds = f.ConnectionEnds
                }).ToArray(),
            Nodes = _nodes.Select(pair => new TrafficAuditNodeRecord
                {
                    IpAddress = pair.Key,
                    FirstSeenUtc = pair.Value.FirstSeenUtc,
                    LastSeenUtc = pair.Value.LastSeenUtc,
                    TxPackets = pair.Value.TxPackets,
                    RxPackets = pair.Value.RxPackets,
                    TxBytes = pair.Value.TxBytes,
                    RxBytes = pair.Value.RxBytes
                })
                .OrderByDescending(n => n.TotalBytes)
                .Take(maxNodes)
                .ToArray()
        };
    }
}
