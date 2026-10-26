namespace NetLoom.App.Models;

public sealed class DeviceClassification
{
    public DeviceType Type { get; init; } = DeviceType.Unknown;
    public int Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = Array.Empty<string>();
}
