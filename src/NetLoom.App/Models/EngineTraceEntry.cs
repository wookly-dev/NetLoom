using System.Globalization;

namespace NetLoom.App.Models;

public enum EngineTraceVerbosity
{
    General = 0,
    Detailed = 1,
    Raw = 2
}

public sealed class EngineTraceEntry
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public string TimeText => Timestamp.ToString("HH:mm:ss.fff", CultureInfo.InvariantCulture);
    public string Category { get; init; } = "INFO";
    public string IpAddress { get; init; } = "";
    public string Message { get; init; } = "";
    public EngineTraceVerbosity Verbosity { get; init; } = EngineTraceVerbosity.General;
}
