namespace NetLoom.App.Models;

public sealed class AdapterInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Address { get; init; } = "";
    public int PrefixLength { get; init; }
    public string GatewayAddress { get; init; } = "";
    public string InterfaceId { get; init; } = "";
    public bool IsWireless { get; init; }
    public string Cidr => $"{Address}/{PrefixLength}";
    public string Display
    {
        get
        {
            var kind = IsWireless ? "Wi-Fi · " : "";
            return string.IsNullOrWhiteSpace(GatewayAddress)
                ? $"{kind}{Name}  ·  {Address}/{PrefixLength}"
                : $"{kind}{Name}  ·  {Address}/{PrefixLength}  ·  GW {GatewayAddress}";
        }
    }
}
