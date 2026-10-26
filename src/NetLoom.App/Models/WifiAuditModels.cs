namespace NetLoom.App.Models;

public sealed class WifiAuditResult
{
    public DateTime AuditedAt { get; init; } = DateTime.Now;
    public string AdapterName { get; init; } = "";
    public string AdapterDescription { get; init; } = "";
    public string InterfaceId { get; init; } = "";
    public bool Supported { get; init; }
    public string StatusMessage { get; init; } = "";
    public WifiNetworkInfo? CurrentNetwork { get; init; }
    public IReadOnlyList<WifiNetworkInfo> Networks { get; init; } = Array.Empty<WifiNetworkInfo>();
    public IReadOnlyList<WifiAuditFinding> Findings { get; init; } = Array.Empty<WifiAuditFinding>();

    public int HighCount => Findings.Count(x => x.Severity == "HIGH");
    public int MediumCount => Findings.Count(x => x.Severity == "MEDIUM");
    public int InfoCount => Findings.Count(x => x.Severity == "INFO");
}

public sealed class WifiNetworkInfo
{
    public string Ssid { get; init; } = "";
    public string ProfileName { get; init; } = "";
    public string Authentication { get; init; } = "";
    public string Cipher { get; init; } = "";
    public int SignalQuality { get; init; }
    public bool SecurityEnabled { get; init; }
    public bool IsConnected { get; init; }
    public string SecurityGrade { get; init; } = "INFO";
    public string SecuritySummary { get; init; } = "";
    public string ConnectedDisplay => IsConnected ? "연결됨" : "";
    public string SignalDisplay => $"{SignalQuality}%";
}

public sealed class WifiAuditFinding
{
    public string Severity { get; init; } = "INFO";
    public string Ssid { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Recommendation { get; init; } = "";
}
