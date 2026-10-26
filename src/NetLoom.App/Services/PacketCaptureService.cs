using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public sealed class PacketCaptureService : IDisposable
{
    private Socket? _socket;
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private readonly object _coverageSync = new();
    private readonly HashSet<string> _transitInternalHosts = new(StringComparer.OrdinalIgnoreCase);
    private PacketCaptureScopeMode _scopeMode = PacketCaptureScopeMode.LocalHost;
    private long _coverageTotalPackets;
    private long _coverageLocalEndpointPackets;
    private long _coverageTransitPackets;
    private long _coverageTransitExternalPackets;
    private DateTime _lastTransitSeenUtc;

    public bool IsRunning => _captureTask is { IsCompleted: false };
    public string AdapterAddress { get; private set; } = "";
    public PacketCaptureScopeMode ScopeMode => _scopeMode;
    public string CaptureModeText => _scopeMode == PacketCaptureScopeMode.SpanTap
        ? "Windows Raw Socket · SPAN/TAP transit verification · IPv4 metadata"
        : "Windows Raw Socket · Local Host IPv4 metadata + visible application hints";

    public event Action<PacketObservation>? PacketCaptured;
    public event Action<string>? CaptureStopped;

    public Task StartAsync(AdapterInfo adapter, PacketCaptureScopeMode scopeMode = PacketCaptureScopeMode.LocalHost)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("패킷 캡처는 Windows에서만 지원합니다.");
        if (IsRunning)
            return Task.CompletedTask;
        if (!IPAddress.TryParse(adapter.Address, out var localIp) || localIp.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("선택 어댑터의 IPv4 주소가 올바르지 않습니다.");

        Stop();
        AdapterAddress = adapter.Address;
        _scopeMode = scopeMode;
        ResetCoverageCounters();
        _cts = new CancellationTokenSource();

        try
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP)
            {
                ReceiveBufferSize = 1024 * 1024
            };
            _socket.Bind(new IPEndPoint(localIp, 0));
            _socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
        }
        catch
        {
            _socket?.Dispose();
            _socket = null;
            _cts.Dispose();
            _cts = null;
            throw;
        }

        var socket = _socket;
        var token = _cts.Token;
        _captureTask = Task.Run(() => CaptureLoopAsync(socket, token));
        return Task.CompletedTask;
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try
        {
            if (_socket is not null)
            {
                try { _socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(0), null); } catch { }
                _socket.Dispose();
            }
        }
        catch { }
        finally
        {
            _socket = null;
            _cts?.Dispose();
            _cts = null;
            _captureTask = null;
        }
    }


    public CaptureCoverageSnapshot TakeCoverageSnapshot(bool allowLocalExternalTopology = false)
    {
        lock (_coverageSync)
        {
            return new CaptureCoverageSnapshot
            {
                Mode = _scopeMode,
                IsRunning = IsRunning,
                AdapterAddress = AdapterAddress,
                TotalPackets = _coverageTotalPackets,
                LocalEndpointPackets = _coverageLocalEndpointPackets,
                TransitPackets = _coverageTransitPackets,
                TransitExternalPackets = _coverageTransitExternalPackets,
                TransitInternalHostCount = _transitInternalHosts.Count,
                LastTransitSeenUtc = _lastTransitSeenUtc,
                AllowLocalExternalTopology = allowLocalExternalTopology
            };
        }
    }

    private void ResetCoverageCounters()
    {
        lock (_coverageSync)
        {
            _coverageTotalPackets = 0;
            _coverageLocalEndpointPackets = 0;
            _coverageTransitPackets = 0;
            _coverageTransitExternalPackets = 0;
            _lastTransitSeenUtc = default;
            _transitInternalHosts.Clear();
        }
    }

    private void TrackCoverage(PacketObservation packet)
    {
        lock (_coverageSync)
        {
            _coverageTotalPackets++;
            bool sourceLocal = string.Equals(packet.SourceIp, AdapterAddress, StringComparison.OrdinalIgnoreCase);
            bool destinationLocal = string.Equals(packet.DestinationIp, AdapterAddress, StringComparison.OrdinalIgnoreCase);
            if (sourceLocal || destinationLocal)
            {
                _coverageLocalEndpointPackets++;
                return;
            }

            if (!IsUsefulUnicastIpv4(packet.SourceIp) || !IsUsefulUnicastIpv4(packet.DestinationIp))
                return;

            _coverageTransitPackets++;
            _lastTransitSeenUtc = packet.Timestamp == default ? DateTime.UtcNow : packet.Timestamp;

            bool sourcePrivate = IsPrivateIpv4(packet.SourceIp);
            bool destinationPrivate = IsPrivateIpv4(packet.DestinationIp);
            if (sourcePrivate) AddTransitInternalHost(packet.SourceIp);
            if (destinationPrivate) AddTransitInternalHost(packet.DestinationIp);
            if (sourcePrivate != destinationPrivate)
                _coverageTransitExternalPackets++;
        }
    }

    private void AddTransitInternalHost(string ip)
    {
        if (_transitInternalHosts.Count >= 4096) return;
        _transitInternalHosts.Add(ip);
    }

    private static bool IsUsefulUnicastIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        if (b[0] == 0 || b[0] == 127 || b[0] >= 224) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return false;
        return true;
    }

    private static bool IsPrivateIpv4(string value)
    {
        if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        if (b[0] == 10) return true;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
        return false;
    }

    private async Task CaptureLoopAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];
        string stopReason = "사용자 중지";
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                int received = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancellationToken);
                if (received <= 0) continue;
                if (TryParseIpv4(buffer.AsSpan(0, received), out var packet))
                {
                    TrackCoverage(packet);
                    PacketCaptured?.Invoke(packet);
                }
            }
        }
        catch (OperationCanceledException)
        {
            stopReason = "사용자 중지";
        }
        catch (ObjectDisposedException)
        {
            stopReason = "캡처 종료";
        }
        catch (SocketException ex)
        {
            stopReason = $"Socket {ex.SocketErrorCode}";
        }
        catch (Exception ex)
        {
            stopReason = ex.GetType().Name;
        }
        finally
        {
            CaptureStopped?.Invoke(stopReason);
        }
    }

    private static bool TryParseIpv4(ReadOnlySpan<byte> packet, out PacketObservation observation)
    {
        observation = new PacketObservation();
        if (packet.Length < 20) return false;
        int version = packet[0] >> 4;
        int headerLength = (packet[0] & 0x0F) * 4;
        if (version != 4 || headerLength < 20 || packet.Length < headerLength) return false;

        int totalLength = (packet[2] << 8) | packet[3];
        int length = totalLength > 0 ? Math.Min(totalLength, packet.Length) : packet.Length;
        byte protocolNumber = packet[9];
        int fragmentField = (packet[6] << 8) | packet[7];
        bool firstFragment = (fragmentField & 0x1FFF) == 0;
        string source = new IPAddress(packet.Slice(12, 4).ToArray()).ToString();
        string destination = new IPAddress(packet.Slice(16, 4).ToArray()).ToString();
        int? sourcePort = null;
        int? destinationPort = null;
        byte tcpFlags = 0;
        string protocol;
        int payloadOffset = length;

        switch (protocolNumber)
        {
            case 6:
                protocol = "TCP";
                if (firstFragment && length >= headerLength + 20)
                {
                    sourcePort = (packet[headerLength] << 8) | packet[headerLength + 1];
                    destinationPort = (packet[headerLength + 2] << 8) | packet[headerLength + 3];
                    tcpFlags = packet[headerLength + 13];
                    int tcpHeaderLength = ((packet[headerLength + 12] >> 4) & 0x0F) * 4;
                    if (tcpHeaderLength >= 20 && length >= headerLength + tcpHeaderLength)
                        payloadOffset = headerLength + tcpHeaderLength;
                }
                break;
            case 17:
                protocol = "UDP";
                if (firstFragment && length >= headerLength + 8)
                {
                    sourcePort = (packet[headerLength] << 8) | packet[headerLength + 1];
                    destinationPort = (packet[headerLength + 2] << 8) | packet[headerLength + 3];
                    payloadOffset = headerLength + 8;
                }
                break;
            case 1:
                protocol = "ICMP";
                if (length >= headerLength + 8) payloadOffset = headerLength + 8;
                break;
            case 2:
                protocol = "IGMP";
                break;
            default:
                protocol = $"IP/{protocolNumber}";
                break;
        }

        ReadOnlySpan<byte> payload = payloadOffset < length ? packet.Slice(payloadOffset, length - payloadOffset) : ReadOnlySpan<byte>.Empty;
        var inspection = InspectApplication(protocol, sourcePort, destinationPort, payload);

        observation = new PacketObservation
        {
            Timestamp = DateTime.UtcNow,
            SourceIp = source,
            DestinationIp = destination,
            Protocol = protocol,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            Length = Math.Max(1, length),
            TcpFlags = tcpFlags,
            ApplicationSummary = inspection.Summary,
            PayloadPreview = inspection.Preview,
            InspectionText = inspection.SearchText,
            DnsQueryName = inspection.DnsQueryName,
            DnsRecordType = inspection.DnsRecordType,
            DnsIsResponse = inspection.DnsIsResponse,
            DnsResponseCode = inspection.DnsResponseCode
        };
        return true;
    }

    private readonly record struct ApplicationInspection(
        string Summary, string Preview, string SearchText,
        string DnsQueryName = "", string DnsRecordType = "", bool? DnsIsResponse = null, int? DnsResponseCode = null);

    private readonly record struct DnsInspection(string QueryName, string RecordType, bool IsResponse, int ResponseCode)
    {
        public string ResponseText => ResponseCode switch
        {
            0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED",
            _ => $"RCODE{ResponseCode}"
        };
    }

    private static ApplicationInspection InspectApplication(string protocol, int? sourcePort, int? destinationPort, ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty) return new ApplicationInspection("", "", "");
        int port = ChooseApplicationPort(sourcePort, destinationPort);

        if ((port == 53 || sourcePort == 53) && TryParseDns(payload, string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase), out var dns))
        {
            string suffix = dns.IsResponse ? $" · {dns.ResponseText}" : "";
            string dnsSummary = $"DNS · {dns.QueryName} · {dns.RecordType}{suffix}";
            return new ApplicationInspection(dnsSummary, "", $"{dns.QueryName} {dns.RecordType} {dns.ResponseText}", dns.QueryName, dns.RecordType, dns.IsResponse, dns.ResponseCode);
        }

        if (string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase) && TryParseTlsClientHelloSni(payload, out var sni))
            return new ApplicationInspection($"TLS ClientHello · SNI {sni}", "암호화 세션 · 본문 복호화 없음", sni);

        string searchable = ToPrintableText(payload, 2048);
        if (string.IsNullOrWhiteSpace(searchable)) return new ApplicationInspection("", "", "");

        if (TryDescribeHttp(searchable, out var httpSummary, out var httpPreview))
            return new ApplicationInspection(httpSummary, httpPreview, searchable);

        string preview = Short(RedactSensitiveText(searchable), 384);
        string summary = port switch
        {
            20 or 21 => "FTP plaintext",
            23 => "TELNET plaintext",
            25 or 465 or 587 => "SMTP payload",
            110 or 995 => "POP3 payload",
            143 or 993 => "IMAP payload",
            5060 => "SIP payload",
            _ => ""
        };
        return new ApplicationInspection(summary, preview, searchable);
    }

    private static int ChooseApplicationPort(int? sourcePort, int? destinationPort)
    {
        static bool Known(int port) => port is 20 or 21 or 23 or 25 or 53 or 80 or 110 or 143 or 443 or 465 or 587 or 993 or 995 or 5060;
        if (destinationPort is int dp && Known(dp)) return dp;
        if (sourcePort is int sp && Known(sp)) return sp;
        return destinationPort ?? sourcePort ?? 0;
    }

    private static bool TryDescribeHttp(string text, out string summary, out string preview)
    {
        summary = "";
        preview = "";
        string normalized = text.Replace("\r\n", "\n");
        var lines = normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0) return false;
        string first = lines[0];
        string[] methods = { "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT " };
        bool request = methods.Any(m => first.StartsWith(m, StringComparison.OrdinalIgnoreCase));
        bool response = first.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase);
        if (!request && !response) return false;

        string host = lines.FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) ?? "";
        host = host.Length > 5 ? host[5..].Trim() : "";
        string safeFirst = RedactSensitiveText(first);
        summary = request
            ? $"HTTP · {Short(safeFirst, 120)}{(string.IsNullOrWhiteSpace(host) ? "" : $" · Host {Short(host, 80)}")}"
            : $"HTTP · {Short(safeFirst, 140)}";
        preview = RedactSensitiveText(string.Join(" | ", lines.Take(8)));
        return true;
    }

    private static bool TryParseDns(ReadOnlySpan<byte> payload, bool tcp, out DnsInspection result)
    {
        result = default;
        int offset = 0;
        if (tcp)
        {
            if (payload.Length < 14) return false;
            int declared = (payload[0] << 8) | payload[1];
            if (declared <= 0 || declared + 2 > payload.Length) return false;
            offset = 2;
        }
        if (payload.Length - offset < 12) return false;
        int flags = (payload[offset + 2] << 8) | payload[offset + 3];
        bool isResponse = (flags & 0x8000) != 0;
        int responseCode = flags & 0x000F;
        int qdCount = (payload[offset + 4] << 8) | payload[offset + 5];
        if (qdCount <= 0) return false;
        int pos = offset + 12;
        var labels = new List<string>();
        while (pos < payload.Length)
        {
            int len = payload[pos++];
            if (len == 0) break;
            if ((len & 0xC0) != 0 || len > 63 || pos + len > payload.Length) return false;
            string label = Encoding.ASCII.GetString(payload.Slice(pos, len));
            if (label.Any(ch => char.IsControl(ch))) return false;
            labels.Add(label);
            pos += len;
            if (labels.Count > 30) return false;
        }
        if (labels.Count == 0 || pos + 4 > payload.Length) return false;
        int qtype = (payload[pos] << 8) | payload[pos + 1];
        string type = qtype switch { 1 => "A", 28 => "AAAA", 5 => "CNAME", 15 => "MX", 12 => "PTR", 16 => "TXT", 33 => "SRV", 65 => "HTTPS", _ => $"TYPE{qtype}" };
        result = new DnsInspection(string.Join('.', labels), type, isResponse, responseCode);
        return true;
    }

    private static bool TryParseTlsClientHelloSni(ReadOnlySpan<byte> data, out string sni)
    {
        sni = "";
        try
        {
            if (data.Length < 9 || data[0] != 22) return false;
            int recordLength = (data[3] << 8) | data[4];
            if (recordLength <= 0 || data.Length < 5 + recordLength) return false;
            int pos = 5;
            if (data[pos] != 1 || data.Length < pos + 4) return false;
            pos += 4;
            if (data.Length < pos + 2 + 32 + 1) return false;
            pos += 2 + 32;
            int sessionLength = data[pos++];
            if (data.Length < pos + sessionLength + 2) return false;
            pos += sessionLength;
            int cipherLength = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (data.Length < pos + cipherLength + 1) return false;
            pos += cipherLength;
            int compressionLength = data[pos++];
            if (data.Length < pos + compressionLength + 2) return false;
            pos += compressionLength;
            int extensionsLength = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            int end = Math.Min(data.Length, pos + extensionsLength);
            while (pos + 4 <= end)
            {
                int type = (data[pos] << 8) | data[pos + 1];
                int len = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                if (len < 0 || pos + len > end) return false;
                if (type == 0 && len >= 5)
                {
                    int extPos = pos;
                    int listLen = (data[extPos] << 8) | data[extPos + 1];
                    extPos += 2;
                    int listEnd = Math.Min(pos + len, extPos + listLen);
                    while (extPos + 3 <= listEnd)
                    {
                        int nameType = data[extPos++];
                        int nameLen = (data[extPos] << 8) | data[extPos + 1];
                        extPos += 2;
                        if (extPos + nameLen > listEnd) break;
                        if (nameType == 0 && nameLen > 0)
                        {
                            sni = Encoding.ASCII.GetString(data.Slice(extPos, nameLen));
                            return !string.IsNullOrWhiteSpace(sni);
                        }
                        extPos += nameLen;
                    }
                }
                pos += len;
            }
        }
        catch
        {
        }
        return false;
    }

    private static string ToPrintableText(ReadOnlySpan<byte> payload, int maxBytes)
    {
        int len = Math.Min(payload.Length, Math.Max(1, maxBytes));
        if (len == 0) return "";
        var sb = new StringBuilder(len);
        int printable = 0;
        for (int i = 0; i < len; i++)
        {
            byte b = payload[i];
            if (b is 9 or 10 or 13)
            {
                sb.Append((char)b);
                printable++;
            }
            else if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
                printable++;
            }
            else
            {
                sb.Append(' ');
            }
        }
        if (printable < Math.Min(8, len / 4)) return "";
        // Preserve HTTP header boundaries until protocol parsing and redaction finish.
        return Regex.Replace(sb.ToString(), @"[^\S\r\n]+", " ").Trim();
    }

    private static string RedactSensitiveText(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        string result = value;
        result = Regex.Replace(result, @"(?im)((?:proxy-)?authorization\s*:[ \t]*)[^|\r\n]*", "$1[REDACTED]");
        result = Regex.Replace(result, @"(?im)((?:cookie|set-cookie)\s*:[ \t]*)[^|\r\n]*", "$1[REDACTED]");
        result = Regex.Replace(result, @"(?i)\b(PASS|AUTH)\s+[^|\s]+", "$1 [REDACTED]");
        result = Regex.Replace(result,
            "(?i)(\\b(?:password|passwd|access[_-]?token|refresh[_-]?token|token|api[_-]?key|client[_-]?secret|secret|session)[\\\"']?\\s*[:=]\\s*)(?:\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])*'|[^&|\\s,}]+)",
            "$1[REDACTED]");
        return Short(result, 520);
    }

    private static string Short(string value, int max) => value.Length <= max ? value : value[..Math.Max(1, max - 1)] + "…";

    public void Dispose() => Stop();
}
