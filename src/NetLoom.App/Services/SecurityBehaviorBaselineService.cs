using System.IO;
using System.Text.Json;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

/// <summary>
/// Persistent metadata-only behavior baseline. The baseline is intentionally separate from the
/// volatile relationship-analysis session so "보안 분석 초기화" does not erase learned normal behavior.
/// </summary>
public sealed class SecurityBehaviorBaselineService
{
    private static readonly TimeSpan MinimumLearnInterval = TimeSpan.FromSeconds(55);
    private static readonly TimeSpan SaveInterval = TimeSpan.FromMinutes(2);
    private const int OverallReadySamples = 20;
    private const int HourlyReadySamples = 8;

    private readonly object _sync = new();
    private readonly string _path;
    private SecurityBehaviorBaselineDocument _document;
    private readonly Dictionary<string, DateTime> _lastLearnUtc = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastSavedUtc;
    private bool _dirty;

    public SecurityBehaviorBaselineService()
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WooklyDev",
            "NetLoom");
        _path = Path.Combine(directory, "security-baseline.json");
        _document = Load(_path);
        NormalizeDocument(_document);
    }

    public string StoragePath => _path;

    public SecurityBaselineEvaluation Evaluate(string ipAddress, DateTime nowUtc, SecurityBehaviorSample sample)
    {
        lock (_sync)
        {
            if (!_document.Devices.TryGetValue(ipAddress, out var profile))
                return new SecurityBaselineEvaluation { SampleCount = 0 };

            int localHour = nowUtc.ToLocalTime().Hour;
            SecurityBaselineBucket? bucket = null;
            string scope = "전체 시간대";
            if (profile.Hourly.TryGetValue(localHour, out var hourly) && hourly.Samples >= HourlyReadySamples)
            {
                bucket = hourly;
                scope = $"{localHour:00}시 시간대";
            }
            else if (profile.Overall.Samples >= OverallReadySamples)
            {
                bucket = profile.Overall;
            }

            int samples = bucket?.Samples ?? profile.Overall.Samples;
            if (bucket is null)
                return new SecurityBaselineEvaluation { SampleCount = samples, ScopeText = scope };

            var reasons = new List<string>();
            int score = 0;
            double fanOutZ = ScoreMetric("외부 fan-out", sample.ExternalFanOut5m, bucket.ExternalFanOut5m, 3, 8, ref score, reasons);
            double startsZ = ScoreMetric("외부 연결시도", sample.ExternalConnectionStarts5m, bucket.ExternalConnectionStarts5m, 5, 12, ref score, reasons);
            double bytesZ = ScoreMetric("외부 트래픽", sample.ExternalBytes5m, bucket.ExternalBytes5m, 256 * 1024, 1 * 1024 * 1024, ref score, reasons, formatBytes: true);
            double outboundZ = ScoreMetric("외부 송신량", sample.OutboundExternalBytes5m, bucket.OutboundExternalBytes5m, 128 * 1024, 512 * 1024, ref score, reasons, formatBytes: true);
            double managementZ = ScoreMetric("내부 관리포트 대상", sample.InternalManagementTargets5m, bucket.InternalManagementTargets5m, 2, 4, ref score, reasons);

            return new SecurityBaselineEvaluation
            {
                IsReady = true,
                SampleCount = samples,
                ScopeText = scope,
                AnomalyScore = Math.Clamp(score, 0, 100),
                FanOutZ = fanOutZ,
                ConnectionStartsZ = startsZ,
                ExternalBytesZ = bytesZ,
                OutboundBytesZ = outboundZ,
                ManagementTargetsZ = managementZ,
                Reasons = reasons
            };
        }
    }

    public bool TryLearn(string ipAddress, DateTime nowUtc, SecurityBehaviorSample sample, bool eligible)
    {
        if (!eligible || string.IsNullOrWhiteSpace(ipAddress)) return false;

        lock (_sync)
        {
            if (_lastLearnUtc.TryGetValue(ipAddress, out var last) && nowUtc - last < MinimumLearnInterval)
                return false;

            if (!_document.Devices.TryGetValue(ipAddress, out var profile))
            {
                profile = new SecurityDeviceBaselineProfile
                {
                    IpAddress = ipAddress,
                    FirstLearnedUtc = nowUtc,
                    LastLearnedUtc = nowUtc
                };
                _document.Devices[ipAddress] = profile;
            }

            int localHour = nowUtc.ToLocalTime().Hour;
            if (!profile.Hourly.TryGetValue(localHour, out var hourly))
            {
                hourly = new SecurityBaselineBucket();
                profile.Hourly[localHour] = hourly;
            }

            profile.Overall.Update(sample);
            hourly.Update(sample);
            profile.LastLearnedUtc = nowUtc;
            if (profile.FirstLearnedUtc == default) profile.FirstLearnedUtc = nowUtc;
            _lastLearnUtc[ipAddress] = nowUtc;
            _document.UpdatedUtc = nowUtc;
            _dirty = true;

            Cleanup(nowUtc);
            SaveIfDue(nowUtc);
            return true;
        }
    }

    public void Reset()
    {
        lock (_sync)
        {
            _document = new SecurityBehaviorBaselineDocument { UpdatedUtc = DateTime.UtcNow };
            _lastLearnUtc.Clear();
            _dirty = true;
            SaveCore();
        }
    }

    public void Flush()
    {
        lock (_sync)
        {
            if (_dirty) SaveCore();
        }
    }

    public int DeviceCount
    {
        get { lock (_sync) return _document.Devices.Count; }
    }

    private void SaveIfDue(DateTime nowUtc)
    {
        if (!_dirty || (nowUtc - _lastSavedUtc) < SaveInterval) return;
        SaveCore();
    }

    private void SaveCore()
    {
        try
        {
            string? directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            _document.UpdatedUtc = DateTime.UtcNow;
            string json = JsonSerializer.Serialize(_document, new JsonSerializerOptions { WriteIndented = true });
            string temp = _path + ".tmp";
            File.WriteAllText(temp, json);
            File.Move(temp, _path, true);
            _dirty = false;
            _lastSavedUtc = DateTime.UtcNow;
        }
        catch
        {
            // Baseline persistence failure must never stop packet capture or the audit UI.
        }
    }

    private static SecurityBehaviorBaselineDocument Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return new SecurityBehaviorBaselineDocument();
            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<SecurityBehaviorBaselineDocument>(json) ?? new SecurityBehaviorBaselineDocument();
        }
        catch
        {
            return new SecurityBehaviorBaselineDocument();
        }
    }

    private static void NormalizeDocument(SecurityBehaviorBaselineDocument document)
    {
        document.Devices ??= new Dictionary<string, SecurityDeviceBaselineProfile>(StringComparer.OrdinalIgnoreCase);
        if (document.Devices.Comparer != StringComparer.OrdinalIgnoreCase)
            document.Devices = new Dictionary<string, SecurityDeviceBaselineProfile>(document.Devices, StringComparer.OrdinalIgnoreCase);

        foreach (var pair in document.Devices)
        {
            var profile = pair.Value;
            profile.IpAddress = string.IsNullOrWhiteSpace(profile.IpAddress) ? pair.Key : profile.IpAddress;
            profile.Overall ??= new SecurityBaselineBucket();
            profile.Hourly ??= new Dictionary<int, SecurityBaselineBucket>();
        }
    }

    private void Cleanup(DateTime nowUtc)
    {
        DateTime cutoff = nowUtc - TimeSpan.FromDays(45);
        foreach (string key in _document.Devices
                     .Where(p => p.Value.LastLearnedUtc != default && p.Value.LastLearnedUtc < cutoff)
                     .OrderBy(p => p.Value.LastLearnedUtc)
                     .Select(p => p.Key)
                     .ToArray())
            _document.Devices.Remove(key);

        if (_document.Devices.Count > 2048)
        {
            foreach (string key in _document.Devices
                         .OrderBy(p => p.Value.LastLearnedUtc)
                         .Take(_document.Devices.Count - 1536)
                         .Select(p => p.Key)
                         .ToArray())
                _document.Devices.Remove(key);
        }
    }

    private static double ScoreMetric(
        string label,
        double current,
        SecurityMetricStats stats,
        double absoluteSoftDelta,
        double absoluteHardDelta,
        ref int score,
        List<string> reasons,
        bool formatBytes = false)
    {
        if (stats.Samples < 2) return 0;
        double std = Math.Max(stats.StandardDeviation, Math.Max(1.0, Math.Abs(stats.Mean) * 0.12));
        double z = (current - stats.Mean) / std;
        double delta = current - stats.Mean;
        double ratio = stats.Mean > 0.001 ? current / stats.Mean : (current > 0 ? 99 : 1);

        bool hard = z >= 4.0 && delta >= absoluteHardDelta && ratio >= 1.8;
        bool soft = z >= 2.7 && delta >= absoluteSoftDelta && ratio >= 1.45;
        if (hard)
        {
            score += 24;
            reasons.Add($"{label} {Format(current, formatBytes)} · 평소 {Format(stats.Mean, formatBytes)} 대비 크게 증가");
        }
        else if (soft)
        {
            score += 12;
            reasons.Add($"{label} {Format(current, formatBytes)} · 평소 {Format(stats.Mean, formatBytes)} 대비 증가");
        }
        return z;
    }

    private static string Format(double value, bool bytes)
    {
        if (!bytes) return value.ToString("0.0");
        return TrafficAuditFlowRecord.FormatBytes((long)Math.Max(0, value));
    }
}
