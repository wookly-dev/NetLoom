using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class NetworkAdapterService
{
    public static IReadOnlyList<AdapterInfo> GetAdapters()
    {
        var result = new List<AdapterInfo>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                 n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var props = nic.GetIPProperties();
            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?
                .ToString() ?? "";

            foreach (var uni in props.UnicastAddresses.Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
            {
                result.Add(new AdapterInfo
                {
                    Name = nic.Name,
                    Description = nic.Description,
                    Address = uni.Address.ToString(),
                    PrefixLength = uni.PrefixLength,
                    GatewayAddress = gateway,
                    InterfaceId = nic.Id,
                    IsWireless = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                });
            }
        }

        return result
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(a => a.Address, StringComparer.Ordinal)
            .ToList();
    }
}
