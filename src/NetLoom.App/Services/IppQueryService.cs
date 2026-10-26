using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class IppQueryService
{
    private static readonly string[] CandidatePaths = { "/ipp/print", "/ipp/printer", "/printers/", "/" };
    private static readonly string[] RequestedAttributes =
    {
        "printer-name",
        "printer-make-and-model",
        "printer-info",
        "printer-location",
        "printer-state",
        "printer-state-reasons",
        "printer-uuid",
        "color-supported",
        "sides-supported"
    };

    public static async Task<IppPrinterInfo> QueryAsync(
        IPAddress ip,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        using var handler = new HttpClientHandler
        {
            UseProxy = false,
            AllowAutoRedirect = true
        };
        using var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };

        string lastStatus = "IPP 응답 없음";
        foreach (string path in CandidatePaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string printerUri = $"ipp://{ip}{path}";
            string httpUri = $"http://{ip}:631{path}";

            try
            {
                byte[] body = BuildRequest(printerUri, Environment.TickCount & 0x7fffffff);
                using var request = new HttpRequestMessage(HttpMethod.Post, httpUri);
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/ipp");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/ipp"));
                request.Headers.UserAgent.ParseAdd("NetLoom/0.3.9");

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(Math.Clamp(timeoutMs * 2, 500, 6000));

                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeoutCts.Token);
                if (!response.IsSuccessStatusCode)
                {
                    lastStatus = $"HTTP {(int)response.StatusCode}";
                    continue;
                }

                var bytes = await response.Content.ReadAsByteArrayAsync(timeoutCts.Token);
                if (bytes.Length < 8)
                {
                    lastStatus = "IPP 응답 형식 오류";
                    continue;
                }

                var parsed = ParseResponse(bytes);
                if (!parsed.Success)
                {
                    lastStatus = parsed.Status;
                    continue;
                }

                return new IppPrinterInfo
                {
                    Attempted = true,
                    Success = true,
                    Status = "IPP Get-Printer-Attributes 성공",
                    PrinterUri = printerUri,
                    PrinterName = parsed.First("printer-name"),
                    MakeAndModel = parsed.First("printer-make-and-model"),
                    PrinterInfo = parsed.First("printer-info"),
                    Location = parsed.First("printer-location"),
                    PrinterState = MapPrinterState(parsed.First("printer-state")),
                    PrinterStateReasons = string.Join(", ", parsed.All("printer-state-reasons")),
                    PrinterUuid = parsed.First("printer-uuid"),
                    ColorSupported = ParseBool(parsed.First("color-supported")),
                    SidesSupported = string.Join(", ", parsed.All("sides-supported"))
                };
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lastStatus = "IPP timeout";
            }
            catch (HttpRequestException ex)
            {
                lastStatus = $"IPP HTTP 오류 · {ex.GetType().Name}";
            }
            catch (Exception ex)
            {
                lastStatus = $"IPP 해석 오류 · {ex.GetType().Name}";
            }
        }

        return new IppPrinterInfo
        {
            Attempted = true,
            Success = false,
            Status = lastStatus
        };
    }

    private sealed class ParsedIpp
    {
        public bool Success { get; init; }
        public string Status { get; init; } = "";
        public Dictionary<string, List<string>> Attributes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string First(string name) => Attributes.TryGetValue(name, out var list) && list.Count > 0 ? list[0] : "";
        public IReadOnlyList<string> All(string name) => Attributes.TryGetValue(name, out var list) ? list : Array.Empty<string>();
    }

    private static ParsedIpp ParseResponse(byte[] data)
    {
        ushort statusCode = ReadUInt16(data, 2);
        bool success = statusCode < 0x0400;
        var attrs = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        int offset = 8;
        string lastName = "";

        while (offset < data.Length)
        {
            byte tag = data[offset++];
            if (tag == 0x03) break;
            if (tag <= 0x0F)
            {
                lastName = "";
                continue;
            }

            if (offset + 2 > data.Length) break;
            int nameLength = ReadUInt16(data, offset);
            offset += 2;
            if (offset + nameLength > data.Length) break;

            string name = nameLength > 0
                ? Encoding.UTF8.GetString(data, offset, nameLength)
                : lastName;
            offset += nameLength;
            if (nameLength > 0) lastName = name;

            if (offset + 2 > data.Length) break;
            int valueLength = ReadUInt16(data, offset);
            offset += 2;
            if (offset + valueLength > data.Length) break;

            var valueBytes = data.AsSpan(offset, valueLength);
            offset += valueLength;
            if (string.IsNullOrWhiteSpace(name)) continue;

            string value = DecodeValue(tag, valueBytes);
            if (!attrs.TryGetValue(name, out var list))
            {
                list = new List<string>();
                attrs[name] = list;
            }
            if (!string.IsNullOrWhiteSpace(value) && !list.Contains(value, StringComparer.OrdinalIgnoreCase))
                list.Add(value);
        }

        return new ParsedIpp
        {
            Success = success,
            Status = success ? "OK" : $"IPP status 0x{statusCode:X4}",
            Attributes = attrs
        };
    }

    private static string DecodeValue(byte tag, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return "";
        return tag switch
        {
            0x21 or 0x23 when bytes.Length == 4 => ReadInt32(bytes).ToString(),
            0x22 => bytes[0] == 0 ? "false" : "true",
            0x41 or 0x42 or 0x44 or 0x45 or 0x46 or 0x47 or 0x48 or 0x49 => Encoding.UTF8.GetString(bytes).Trim(),
            _ => Encoding.UTF8.GetString(bytes).Trim('\0', ' ', '\r', '\n', '\t')
        };
    }

    private static byte[] BuildRequest(string printerUri, int requestId)
    {
        using var stream = new MemoryStream();
        stream.WriteByte(0x02);
        stream.WriteByte(0x00);
        WriteUInt16(stream, 0x000B);
        WriteInt32(stream, requestId);
        stream.WriteByte(0x01);

        WriteAttribute(stream, 0x47, "attributes-charset", "utf-8");
        WriteAttribute(stream, 0x48, "attributes-natural-language", "ko");
        WriteAttribute(stream, 0x45, "printer-uri", printerUri);

        bool first = true;
        foreach (string attr in RequestedAttributes)
        {
            WriteAttribute(stream, 0x44, first ? "requested-attributes" : "", attr);
            first = false;
        }

        stream.WriteByte(0x03);
        return stream.ToArray();
    }

    private static void WriteAttribute(Stream stream, byte tag, string name, string value)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        stream.WriteByte(tag);
        WriteUInt16(stream, checked((ushort)nameBytes.Length));
        stream.Write(nameBytes, 0, nameBytes.Length);
        WriteUInt16(stream, checked((ushort)valueBytes.Length));
        stream.Write(valueBytes, 0, valueBytes.Length);
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteInt32(Stream stream, int value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static ushort ReadUInt16(byte[] data, int offset) =>
        checked((ushort)((data[offset] << 8) | data[offset + 1]));

    private static int ReadInt32(ReadOnlySpan<byte> data) =>
        (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];

    private static string MapPrinterState(string value) => value switch
    {
        "3" => "idle",
        "4" => "processing",
        "5" => "stopped",
        "" => "",
        _ => value
    };

    private static bool? ParseBool(string value) => value.ToLowerInvariant() switch
    {
        "true" => true,
        "false" => false,
        _ => null
    };
}
