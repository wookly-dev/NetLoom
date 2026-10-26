namespace NetLoom.App.Models;

public enum TopologyCategory
{
    Infrastructure,
    Special,
    Peripheral,
    Endpoint,
    Other,
    External
}

public static class TopologyCategoryExtensions
{
    public static TopologyCategory ToTopologyCategory(this DeviceType type) => type switch
    {
        DeviceType.Router or DeviceType.Switch or DeviceType.Hub or DeviceType.AccessPoint or DeviceType.WifiExtender or DeviceType.Firewall => TopologyCategory.Infrastructure,
        DeviceType.Server or DeviceType.Nas or DeviceType.Hypervisor => TopologyCategory.Special,
        DeviceType.Printer or DeviceType.Camera or DeviceType.Ups or DeviceType.VoipPhone => TopologyCategory.Peripheral,
        DeviceType.Pc or DeviceType.Mobile or DeviceType.IoT => TopologyCategory.Endpoint,
        DeviceType.Internet => TopologyCategory.External,
        _ => TopologyCategory.Other
    };
}
