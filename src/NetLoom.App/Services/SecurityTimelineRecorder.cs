using NetLoom.App.Models;

namespace NetLoom.App.Services;

/// <summary>
/// In-memory metadata-only security timeline. It records metadata relationship snapshots for
/// investigation/replay and is intentionally not persisted across application restarts.
/// </summary>
public sealed class SecurityTimelineRecorder
{
    private readonly object _sync = new();
    private readonly List<SecurityTimelineEntry> _entries = new();
    private DateTime _lastRecordedUtc;
    private string _lastSignature = "";
    private const int MaxEntries = 720;

    public int Count { get { lock (_sync) return _entries.Count; } }

    public void Record(SecurityRelationshipSnapshot snapshot)
    {
        if (snapshot is null || !snapshot.HasData) return;
        DateTime now = snapshot.TimestampUtc == default ? DateTime.UtcNow : snapshot.TimestampUtc;
        string signature = Signature(snapshot);
        lock (_sync)
        {
            bool changed = !string.Equals(signature, _lastSignature, StringComparison.Ordinal);
            if (!changed && now - _lastRecordedUtc < TimeSpan.FromSeconds(30)) return;
            if (changed && now - _lastRecordedUtc < TimeSpan.FromSeconds(5)) return;
            _entries.Add(new SecurityTimelineEntry { TimestampUtc = now, Snapshot = snapshot });
            _lastRecordedUtc = now;
            _lastSignature = signature;
            if (_entries.Count > MaxEntries)
                _entries.RemoveRange(0, _entries.Count - MaxEntries);
        }
    }

    public IReadOnlyList<SecurityTimelineEntry> TakeSnapshot()
    {
        lock (_sync) return _entries.ToArray();
    }

    public void Clear()
    {
        lock (_sync)
        {
            _entries.Clear();
            _lastRecordedUtc = default;
            _lastSignature = "";
        }
    }

    private static string Signature(SecurityRelationshipSnapshot s)
    {
        string top = string.Join(',', s.Nodes.OrderByDescending(n => n.RiskScore).Take(5).Select(n => $"{n.IpAddress}:{n.RiskScore}:{n.DnsAnomalyScore}:{n.BeaconCandidateCount}:{n.LateralMovementTargetCount}"));
        return $"{s.HighCount}|{s.MediumCount}|{s.WatchCount}|{s.DnsAnomalyNodeCount}|{s.BeaconNodeCount}|{s.LateralMovementNodeCount}|{s.BaselineAnomalyCount}|{top}";
    }
}
