using System.IO;
using System.Text;
using System.Text.Json;
using NetLoom.App.Models;
using NetLoom.App.Helpers;

namespace NetLoom.App.Services;

public static class ExportService
{
    public static async Task ExportCsvAsync(string path, IEnumerable<ScanResult> results)
    {
        static string Escape(string value) => CsvHelper.Escape(value);

        var sb = new StringBuilder();
        sb.AppendLine("Audit Group,Audit Range,Status,Device,IP Address,Host Name,MAC Address,RTT,Open Ports,Protocol Identity,SNMP Name,SNMP Description,IPP Model,Gateway,SMB Audit,Shares,Guest Accessible Shares");

        foreach (var r in results)
        {
            sb.Append(Escape(r.AuditGroupLabel)).Append(',')
              .Append(Escape(r.AuditGroupExpression)).Append(',')
              .Append(Escape(r.Status)).Append(',')
              .Append(Escape(r.DeviceLabel)).Append(',')
              .Append(Escape(r.IpAddress)).Append(',')
              .Append(Escape(r.HostName)).Append(',')
              .Append(Escape(r.MacAddress)).Append(',')
              .Append(Escape(r.RoundTripDisplay)).Append(',')
              .Append(Escape(r.OpenPorts)).Append(',')
              .Append(Escape(r.ProtocolIdentitySummary)).Append(',')
              .Append(Escape(r.SnmpInfo.SysName)).Append(',')
              .Append(Escape(r.SnmpInfo.SysDescr)).Append(',')
              .Append(Escape(r.IppInfo.MakeAndModel)).Append(',')
              .Append(r.IsGateway ? "Y" : "N").Append(',')
              .Append(Escape(r.ShareAudit.Summary)).Append(',')
              .Append(Escape(string.Join(" | ", r.ShareAudit.EnumeratedShares))).Append(',')
              .Append(Escape(string.Join(" | ", r.ShareAudit.GuestAccessibleShares))).AppendLine();
        }

        await File.WriteAllTextAsync(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }

    public static async Task ExportJsonAsync(string path, IEnumerable<ScanResult> results)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        await File.WriteAllTextAsync(
            path,
            JsonSerializer.Serialize(results, options),
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }
}
