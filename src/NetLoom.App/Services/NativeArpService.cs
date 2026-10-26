using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace NetLoom.App.Services;

internal static class NativeArpService
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint physicalAddrLen);

    public static string TryGetMacAddress(IPAddress ip)
    {
        if (!OperatingSystem.IsWindows())
            return "";

        try
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return "";

            uint destination = BitConverter.ToUInt32(bytes, 0);
            var mac = new byte[6];
            uint length = (uint)mac.Length;

            int result = SendARP(destination, 0, mac, ref length);
            if (result != 0 || length == 0)
                return "";

            return string.Join(":", mac.Take((int)length).Select(b => b.ToString("X2")));
        }
        catch
        {
            return "";
        }
    }
}
