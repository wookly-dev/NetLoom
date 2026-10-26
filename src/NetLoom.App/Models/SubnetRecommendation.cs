namespace NetLoom.App.Models;

public sealed class SubnetRecommendation
{
    public bool IsSelected { get; set; }
    public string GroupLabel { get; init; } = "";
    public string Cidr { get; init; } = "";
    public string Source { get; init; } = "";
    public string Gateway { get; init; } = "";
    public string InterfaceAddress { get; init; } = "";
    public string Reason { get; init; } = "";
    public int EstimatedHosts { get; init; }
    public string ParentDevice { get; init; } = "";
    public string Reachability { get; init; } = "";
    public string EstimatedHostsText => EstimatedHosts > 0 ? $"{EstimatedHosts:N0} IP" : "-";
}
