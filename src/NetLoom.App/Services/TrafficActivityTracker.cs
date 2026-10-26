using NetLoom.App.Models;

namespace NetLoom.App.Services;

public sealed class TrafficActivityTracker
{
    private sealed class NodeAccumulator
    {
        public long RxBytes;
        public long TxBytes;
        public long RxPackets;
        public long TxPackets;
        public DateTime LastSeenUtc;
        public string LastProtocol = "";
        public int? LastPort;
    }

    private sealed class FlowAccumulator
    {
        public long Bytes;
        public long Packets;
        public DateTime LastSeenUtc;
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, NodeAccumulator> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string SourceIp, string DestinationIp, string Protocol, int? SourcePort, int? DestinationPort, FlowAccumulator Acc)> _flows = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastSnapshotUtc = DateTime.UtcNow;
    private long _totalPackets;
    private long _totalBytes;

    public void Clear()
    {
        lock (_sync)
        {
            _nodes.Clear();
            _flows.Clear();
            _totalPackets = 0;
            _totalBytes = 0;
            _lastSnapshotUtc = DateTime.UtcNow;
        }
    }

    public void Add(PacketObservation packet)
    {
        if (packet.Length <= 0 || string.IsNullOrWhiteSpace(packet.SourceIp) || string.IsNullOrWhiteSpace(packet.DestinationIp))
            return;

        lock (_sync)
        {
            _totalPackets++;
            _totalBytes += packet.Length;

            var source = GetNode(packet.SourceIp);
            source.TxBytes += packet.Length;
            source.TxPackets++;
            source.LastSeenUtc = packet.Timestamp;
            source.LastProtocol = packet.Protocol;
            source.LastPort = packet.DestinationPort ?? packet.SourcePort;

            var destination = GetNode(packet.DestinationIp);
            destination.RxBytes += packet.Length;
            destination.RxPackets++;
            destination.LastSeenUtc = packet.Timestamp;
            destination.LastProtocol = packet.Protocol;
            destination.LastPort = packet.DestinationPort ?? packet.SourcePort;

            string key = $"{packet.SourceIp}|{packet.DestinationIp}|{packet.Protocol}|{packet.SourcePort?.ToString() ?? ""}|{packet.DestinationPort?.ToString() ?? ""}";
            if (!_flows.TryGetValue(key, out var flow))
            {
                flow = (packet.SourceIp, packet.DestinationIp, packet.Protocol, packet.SourcePort, packet.DestinationPort, new FlowAccumulator());
                _flows[key] = flow;
            }
            flow.Acc.Bytes += packet.Length;
            flow.Acc.Packets++;
            flow.Acc.LastSeenUtc = packet.Timestamp;

            // Keep the dictionary bounded under unusually chatty traffic.
            if (_flows.Count > 4096)
            {
                foreach (var oldKey in _flows.OrderBy(kv => kv.Value.Acc.LastSeenUtc).Take(_flows.Count - 3072).Select(kv => kv.Key).ToArray())
                    _flows.Remove(oldKey);
            }
        }
    }

    public TrafficSnapshot TakeSnapshot()
    {
        lock (_sync)
        {
            var now = DateTime.UtcNow;
            double seconds = Math.Clamp((now - _lastSnapshotUtc).TotalSeconds, 0.10, 5.0);
            _lastSnapshotUtc = now;

            var nodes = new Dictionary<string, LiveTrafficNodeStat>(StringComparer.OrdinalIgnoreCase);
            long intervalPackets = 0;
            long intervalBytes = 0;

            foreach (var pair in _nodes.ToArray())
            {
                var a = pair.Value;
                intervalPackets += a.RxPackets + a.TxPackets;
                intervalBytes += a.RxBytes + a.TxBytes;

                bool recent = (now - a.LastSeenUtc) <= TimeSpan.FromSeconds(5);
                if (recent || a.RxPackets > 0 || a.TxPackets > 0)
                {
                    nodes[pair.Key] = new LiveTrafficNodeStat
                    {
                        IpAddress = pair.Key,
                        RxBytesPerSecond = a.RxBytes / seconds,
                        TxBytesPerSecond = a.TxBytes / seconds,
                        RxPacketsPerSecond = a.RxPackets / seconds,
                        TxPacketsPerSecond = a.TxPackets / seconds,
                        LastSeenUtc = a.LastSeenUtc,
                        LastProtocol = a.LastProtocol,
                        LastPort = a.LastPort
                    };
                }

                a.RxBytes = 0;
                a.TxBytes = 0;
                a.RxPackets = 0;
                a.TxPackets = 0;

                if (!recent)
                    _nodes.Remove(pair.Key);
            }

            var flows = _flows.Values
                .Where(f => f.Acc.Packets > 0 || (now - f.Acc.LastSeenUtc) <= TimeSpan.FromSeconds(2))
                .Select(f => new LiveTrafficFlow
                {
                    SourceIp = f.SourceIp,
                    DestinationIp = f.DestinationIp,
                    Protocol = f.Protocol,
                    SourcePort = f.SourcePort,
                    DestinationPort = f.DestinationPort,
                    BytesPerSecond = f.Acc.Bytes / seconds,
                    PacketsPerSecond = f.Acc.Packets / seconds,
                    LastSeenUtc = f.Acc.LastSeenUtc
                })
                .OrderByDescending(f => f.BytesPerSecond)
                .ThenByDescending(f => f.PacketsPerSecond)
                .Take(48)
                .ToArray();

            foreach (var item in _flows.Values)
            {
                item.Acc.Bytes = 0;
                item.Acc.Packets = 0;
            }

            foreach (var oldKey in _flows.Where(kv => (now - kv.Value.Acc.LastSeenUtc) > TimeSpan.FromSeconds(5)).Select(kv => kv.Key).ToArray())
                _flows.Remove(oldKey);

            return new TrafficSnapshot
            {
                TimestampUtc = now,
                Nodes = nodes,
                Flows = flows,
                TotalCapturedPackets = _totalPackets,
                TotalCapturedBytes = _totalBytes,
                CurrentPacketsPerSecond = intervalPackets / seconds,
                CurrentBytesPerSecond = intervalBytes / seconds
            };
        }
    }

    private NodeAccumulator GetNode(string ip)
    {
        if (_nodes.TryGetValue(ip, out var existing)) return existing;
        var node = new NodeAccumulator { LastSeenUtc = DateTime.UtcNow };
        _nodes[ip] = node;
        return node;
    }
}
