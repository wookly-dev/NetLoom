namespace NetLoom.App.Models;

public sealed class CommonPortDefinition
{
    public int Port { get; init; }
    public string Service { get; init; } = "";
    public string Category { get; init; } = "";
    public string Description { get; init; } = "";
}
