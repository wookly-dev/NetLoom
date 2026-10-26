using System.Collections.ObjectModel;

namespace NetLoom.App.Models;

public sealed class MatrixGroup
{
    public string GroupLabel { get; init; } = "";
    public string Expression { get; init; } = "";
    public int HostCount { get; init; }
    public int DisplayedCount => Nodes.Count;
    public ObservableCollection<MatrixNode> Nodes { get; } = new();
    public string HeaderText => $"{GroupLabel}  ·  {Expression}";
    public string CountText => HostCount == DisplayedCount
        ? $"{HostCount:N0} IP"
        : $"{DisplayedCount:N0} / {HostCount:N0} 표시";
}
