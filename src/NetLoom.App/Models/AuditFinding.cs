namespace NetLoom.App.Models;

public sealed class AuditFinding
{
    public string Severity { get; init; } = "INFO";
    public string Category { get; init; } = "";
    public string IpAddress { get; init; } = "";
    public string Title { get; init; } = "";
    public string Evidence { get; init; } = "";
    public string Recommendation { get; init; } = "";
}
