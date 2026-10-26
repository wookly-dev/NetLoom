using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using NetLoom.App.Helpers;
using NetLoom.App.Models;
using NetLoom.App.Services;

internal static class Program
{
    private delegate bool ParsePacket(ReadOnlySpan<byte> bytes, out PacketObservation observation);
    private static int checks;
    private static int failures;

    private static void Check(bool condition, string name)
    {
        checks++;
        if (!condition) { failures++; Console.Error.WriteLine("FAIL: " + name); }
    }

    private static async Task<int> Main()
    {
        var parse = typeof(PacketCaptureService).GetMethod("TryParseIpv4", BindingFlags.NonPublic | BindingFlags.Static)!
            .CreateDelegate<ParsePacket>();
        foreach (var payload in new[]
        {
            "{\"password\":\"fixture-secret\"}",
            "{\"api_key\": \"fixture-secret with spaces\"}",
            "{'client_secret': 'fixture-secret with spaces'}",
            "{\"token\":\"fixture-secret\\\"quoted\"}",
            "password=fixture-secret&ok=1",
            "GET /?token=fixture-secret HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
            "POST / HTTP/1.1\r\nHost: example.invalid\r\nAuthorization: Bearer fixture-secret\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.invalid\r\nCookie: sid=fixture-secret\r\n\r\n",
            "PASS fixture-secret\r\n"
        })
        {
            Check(parse(Packet(payload), out var observation), "synthetic TCP packet parses");
            Check(!observation.PayloadPreview.Contains("fixture-secret") && !observation.ApplicationSummary.Contains("fixture-secret"), "display text masks credential");
            Check(observation.InspectionText.Contains("fixture-secret"), "transient keyword detection retains original visible text");
        }
        Check(parse(Packet("GET /health HTTP/1.1\r\nHost: example.invalid\r\nUser-Agent: fixture\r\n\r\n"), out var http), "HTTP fixture parses");
        Check(http.ApplicationSummary.Contains("Host example.invalid"), "HTTP host is read from its own header line");
        Check(!http.ApplicationSummary.Contains("User-Agent"), "HTTP summary contains request line and host only");
        Check(!parse(new byte[19], out _), "truncated IPv4 is rejected");

        var path = Path.Combine(Path.GetTempPath(), "netloom-regression-" + Guid.NewGuid().ToString("N") + ".csv");
        try
        {
            foreach (var host in new[] { "=1+1", "+1+1", "-1+1", "@SUM(1)", " \t=1+1", "\t=1+1", "\r=1+1" })
            {
                await ExportService.ExportCsvAsync(path, new[] { new ScanResult { HostName = host, IpAddress = "192.0.2.1" } });
                var csv = await File.ReadAllTextAsync(path);
                Check(csv.Contains("'" + host.Replace("\"", "\"\"")), "untrusted CSV cell is forced to text");
            }
            await ExportService.ExportCsvAsync(path, new[] { new ScanResult { HostName = "sample,\"device\"", IpAddress = "192.0.2.1" } });
            Check((await File.ReadAllTextAsync(path)).Contains("\"sample,\"\"device\"\"\""), "CSV delimiters remain escaped");
        }
        finally { File.Delete(path); }

        Check(CidrHelper.EnumerateHosts("192.0.2.0/31").Count == 2, "/31 retains both hosts");
        Check(CidrHelper.EnumerateHosts("192.0.2.7/32").Single().ToString() == "192.0.2.7", "/32 retains exact host");
        Check(ScanTargetParser.Parse("192.0.2.1;192.0.2.1;192.0.2.2").Hosts.Count == 2, "overlapping targets deduplicate");
        try { CidrHelper.EnumerateHosts("10.0.0.0/8"); Check(false, "oversized range rejected"); }
        catch (ArgumentException) { Check(true, "oversized range rejected"); }
        Check(!CidrHelper.IsPrivateOrLocal(IPAddress.Parse("192.0.2.1")), "documentation address is not treated as RFC1918");
        Console.WriteLine($"{checks - failures}/{checks} checks passed; {failures} failed. Synthetic packets only; no network capture or scan.");
        return failures == 0 ? 0 : 1;
    }

    private static byte[] Packet(string payload)
    {
        var body = Encoding.ASCII.GetBytes(payload);
        var packet = new byte[40 + body.Length];
        packet[0] = 0x45;
        packet[2] = (byte)(packet.Length >> 8);
        packet[3] = (byte)packet.Length;
        packet[8] = 64;
        packet[9] = 6;
        new byte[] { 192, 0, 2, 1 }.CopyTo(packet, 12);
        new byte[] { 198, 51, 100, 1 }.CopyTo(packet, 16);
        packet[20] = 0xC0;
        packet[21] = 1;
        packet[23] = 80;
        packet[32] = 0x50;
        packet[33] = 0x18;
        body.CopyTo(packet, 40);
        return packet;
    }
}
