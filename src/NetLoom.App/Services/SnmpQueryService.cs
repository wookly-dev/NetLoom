using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class SnmpQueryService
{
    private static readonly (string Oid, string Name)[] Oids =
    {
        ("1.3.6.1.2.1.1.1.0", "sysDescr"),
        ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
        ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
        ("1.3.6.1.2.1.1.5.0", "sysName"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation"),
        ("1.3.6.1.2.1.4.1.0", "ipForwarding")
    };

    public static async Task<SnmpDeviceInfo> QueryAsync(
        IPAddress ip,
        string community,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(community))
        {
            return new SnmpDeviceInfo
            {
                Attempted = false,
                Success = false,
                Status = "SNMP community 미설정"
            };
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int successCount = 0;
        string lastStatus = "응답 없음";

        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(ip, 161);

        int requestId = Environment.TickCount & 0x3fffffff;
        foreach (var item in Oids)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var request = BuildGetRequest(++requestId, community, item.Oid);
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(Math.Clamp(timeoutMs, 250, 5000));

                await client.SendAsync(request, request.Length).WaitAsync(timeoutCts.Token);
                var response = await client.ReceiveAsync().WaitAsync(timeoutCts.Token);
                var parsed = ParseResponse(response.Buffer);

                if (parsed.ErrorStatus != 0)
                {
                    lastStatus = $"SNMP error {parsed.ErrorStatus}";
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(parsed.Value))
                {
                    values[item.Name] = parsed.Value;
                    successCount++;
                    lastStatus = "SNMP 응답 확인";
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lastStatus = "SNMP timeout";
                if (successCount == 0) break;
            }
            catch (SocketException ex)
            {
                lastStatus = $"SNMP socket error {ex.SocketErrorCode}";
                if (successCount == 0) break;
            }
            catch (Exception ex)
            {
                lastStatus = $"SNMP parse error · {ex.GetType().Name}";
                if (successCount == 0) break;
            }
        }

        values.TryGetValue("sysDescr", out var sysDescr);
        values.TryGetValue("sysObjectID", out var sysObjectId);
        values.TryGetValue("sysName", out var sysName);
        values.TryGetValue("sysLocation", out var sysLocation);
        values.TryGetValue("sysUpTime", out var sysUptime);
        values.TryGetValue("ipForwarding", out var ipForwarding);

        return new SnmpDeviceInfo
        {
            Attempted = true,
            Success = successCount > 0,
            Status = successCount > 0 ? "SNMP v2c 응답 확인" : lastStatus,
            Version = "SNMP v2c",
            SysDescr = sysDescr ?? "",
            SysObjectId = sysObjectId ?? "",
            SysName = sysName ?? "",
            SysLocation = sysLocation ?? "",
            SysUptime = sysUptime ?? "",
            IpForwarding = ipForwarding ?? ""
        };
    }


    public static async Task<SnmpDeviceInfo> QueryNetworkTablesAsync(
        IPAddress ip,
        string community,
        int timeoutMs,
        SnmpDeviceInfo identity,
        CancellationToken cancellationToken)
    {
        if (!identity.Success || string.IsNullOrWhiteSpace(community))
            return identity;

        try
        {
            var addresses = await WalkColumnAsync(ip, community, "1.3.6.1.2.1.4.20.1.1", timeoutMs, 96, cancellationToken);
            var masks = await WalkColumnAsync(ip, community, "1.3.6.1.2.1.4.20.1.3", timeoutMs, 96, cancellationToken);
            var routeDestinations = await WalkColumnAsync(ip, community, "1.3.6.1.2.1.4.21.1.1", timeoutMs, 160, cancellationToken);
            var routeNextHops = await WalkColumnAsync(ip, community, "1.3.6.1.2.1.4.21.1.7", timeoutMs, 160, cancellationToken);
            var routeMasks = await WalkColumnAsync(ip, community, "1.3.6.1.2.1.4.21.1.11", timeoutMs, 160, cancellationToken);

            var interfaces = new List<SnmpIpv4InterfaceInfo>();
            foreach (var pair in addresses)
            {
                string address = pair.Value;
                if (!masks.TryGetValue(pair.Key, out string? mask) ||
                    !TryBuildCidr(address, mask, out string cidr))
                    continue;

                interfaces.Add(new SnmpIpv4InterfaceInfo
                {
                    Address = address,
                    Netmask = mask,
                    Cidr = cidr
                });
            }

            var routes = new List<SnmpRouteInfo>();
            foreach (var pair in routeDestinations)
            {
                string destination = pair.Value;
                if (!routeMasks.TryGetValue(pair.Key, out string? mask) ||
                    !TryBuildCidr(destination, mask, out string cidr))
                    continue;

                routeNextHops.TryGetValue(pair.Key, out string? nextHop);
                routes.Add(new SnmpRouteInfo
                {
                    Destination = destination,
                    Netmask = mask,
                    NextHop = nextHop ?? "",
                    Cidr = cidr
                });
            }

            string status = interfaces.Count == 0 && routes.Count == 0
                ? "SNMP 네트워크 테이블 응답 없음"
                : $"IPv4 interfaces {interfaces.Count} · routes {routes.Count}";

            return CopyWithNetworkTables(identity, interfaces, routes, true, status);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return CopyWithNetworkTables(identity, Array.Empty<SnmpIpv4InterfaceInfo>(), Array.Empty<SnmpRouteInfo>(), true,
                $"SNMP 네트워크 테이블 오류 · {ex.GetType().Name}");
        }
    }

    private static SnmpDeviceInfo CopyWithNetworkTables(
        SnmpDeviceInfo source,
        IReadOnlyList<SnmpIpv4InterfaceInfo> interfaces,
        IReadOnlyList<SnmpRouteInfo> routes,
        bool attempted,
        string status)
    {
        return new SnmpDeviceInfo
        {
            Attempted = source.Attempted,
            Success = source.Success,
            Status = source.Status,
            Version = source.Version,
            SysName = source.SysName,
            SysDescr = source.SysDescr,
            SysObjectId = source.SysObjectId,
            SysLocation = source.SysLocation,
            SysUptime = source.SysUptime,
            IpForwarding = source.IpForwarding,
            Ipv4Interfaces = interfaces,
            Routes = routes,
            NetworkTablesAttempted = attempted,
            NetworkTablesStatus = status
        };
    }

    private static async Task<Dictionary<string, string>> WalkColumnAsync(
        IPAddress ip,
        string community,
        string rootOid,
        int timeoutMs,
        int maxRows,
        CancellationToken cancellationToken)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string currentOid = rootOid;
        int requestId = (Environment.TickCount ^ rootOid.GetHashCode()) & 0x3fffffff;

        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(ip, 161);

        for (int i = 0; i < maxRows; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var request = BuildGetNextRequest(++requestId, community, currentOid);
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(Math.Clamp(timeoutMs, 300, 5000));

                await client.SendAsync(request, request.Length).WaitAsync(timeoutCts.Token);
                var response = await client.ReceiveAsync().WaitAsync(timeoutCts.Token);
                var parsed = ParseResponse(response.Buffer);
                if (parsed.ErrorStatus != 0 || string.IsNullOrWhiteSpace(parsed.Oid))
                    break;

                string expectedPrefix = rootOid + ".";
                if (!parsed.Oid.StartsWith(expectedPrefix, StringComparison.Ordinal))
                    break;
                if (parsed.Value is "endOfMibView" or "noSuchObject" or "noSuchInstance")
                    break;
                if (string.Equals(parsed.Oid, currentOid, StringComparison.Ordinal))
                    break;

                string suffix = parsed.Oid[expectedPrefix.Length..];
                values[suffix] = parsed.Value;
                currentOid = parsed.Oid;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }
            catch (InvalidDataException)
            {
                break;
            }
        }

        return values;
    }

    private static bool TryBuildCidr(string addressText, string maskText, out string cidr)
    {
        cidr = "";
        if (!IPAddress.TryParse(addressText, out var address) || address.AddressFamily != AddressFamily.InterNetwork ||
            !IPAddress.TryParse(maskText, out var mask) || mask.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var maskBytes = mask.GetAddressBytes();
        int prefix = 0;
        bool zeroSeen = false;
        foreach (byte b in maskBytes)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                bool one = (b & (1 << bit)) != 0;
                if (one && zeroSeen) return false;
                if (one) prefix++;
                else zeroSeen = true;
            }
        }

        uint ipValue = ToUInt32(address);
        uint maskValue = ToUInt32(mask);
        uint network = ipValue & maskValue;
        cidr = $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefix}";
        return true;
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    private static byte[] BuildGetNextRequest(int requestId, string community, string oid)
    {
        var varBind = Tlv(0x30,
            Concat(
                Tlv(0x06, EncodeOid(oid)),
                new byte[] { 0x05, 0x00 }));

        var varBindList = Tlv(0x30, varBind);
        var pdu = Tlv(0xA1,
            Concat(
                EncodeInteger(requestId),
                EncodeInteger(0),
                EncodeInteger(0),
                varBindList));

        return Tlv(0x30,
            Concat(
                EncodeInteger(1),
                Tlv(0x04, Encoding.ASCII.GetBytes(community)),
                pdu));
    }

    private static byte[] BuildGetRequest(int requestId, string community, string oid)
    {
        var varBind = Tlv(0x30,
            Concat(
                Tlv(0x06, EncodeOid(oid)),
                new byte[] { 0x05, 0x00 }));

        var varBindList = Tlv(0x30, varBind);
        var pdu = Tlv(0xA0,
            Concat(
                EncodeInteger(requestId),
                EncodeInteger(0),
                EncodeInteger(0),
                varBindList));

        return Tlv(0x30,
            Concat(
                EncodeInteger(1),
                Tlv(0x04, Encoding.ASCII.GetBytes(community)),
                pdu));
    }

    private sealed record ParsedResponse(int ErrorStatus, string Oid, string Value);

    private static ParsedResponse ParseResponse(byte[] packet)
    {
        var root = new BerReader(packet);
        var message = new BerReader(root.ReadExpected(0x30));
        _ = message.ReadInteger();
        _ = message.ReadExpected(0x04);

        var pduContent = message.ReadAny(out byte pduTag);
        if (pduTag != 0xA2)
            throw new InvalidDataException($"Unexpected SNMP PDU 0x{pduTag:X2}");

        var pdu = new BerReader(pduContent);
        _ = pdu.ReadInteger();
        int errorStatus = pdu.ReadInteger();
        _ = pdu.ReadInteger();
        var varBindList = new BerReader(pdu.ReadExpected(0x30));
        var varBind = new BerReader(varBindList.ReadExpected(0x30));
        string oid = DecodeOid(varBind.ReadExpected(0x06));
        var valueBytes = varBind.ReadAny(out byte valueTag);
        string value = DecodeValue(valueTag, valueBytes);
        return new ParsedResponse(errorStatus, oid, value);
    }

    private static string DecodeValue(byte tag, ReadOnlySpan<byte> value)
    {
        return tag switch
        {
            0x02 => DecodeSignedInteger(value).ToString(),
            0x04 => DecodeText(value),
            0x05 => "",
            0x06 => DecodeOid(value),
            0x40 when value.Length == 4 => new IPAddress(value.ToArray()).ToString(),
            0x41 or 0x42 or 0x43 or 0x46 => DecodeUnsignedInteger(value).ToString(),
            0x80 => "noSuchObject",
            0x81 => "noSuchInstance",
            0x82 => "endOfMibView",
            _ => Convert.ToHexString(value)
        };
    }

    private static string DecodeText(ReadOnlySpan<byte> value)
    {
        if (value.Length == 0) return "";
        try
        {
            string utf8 = Encoding.UTF8.GetString(value);
            if (!utf8.Contains('\uFFFD')) return utf8.Trim('\0', ' ', '\r', '\n', '\t');
        }
        catch
        {
        }
        return Encoding.Latin1.GetString(value).Trim('\0', ' ', '\r', '\n', '\t');
    }

    private static byte[] EncodeInteger(int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian) Array.Reverse(bytes);

        int start = 0;
        while (start < bytes.Length - 1)
        {
            bool canTrimPositive = bytes[start] == 0x00 && (bytes[start + 1] & 0x80) == 0;
            bool canTrimNegative = bytes[start] == 0xFF && (bytes[start + 1] & 0x80) != 0;
            if (!canTrimPositive && !canTrimNegative) break;
            start++;
        }

        return Tlv(0x02, bytes[start..]);
    }

    private static long DecodeSignedInteger(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        long value = (data[0] & 0x80) != 0 ? -1 : 0;
        foreach (byte b in data) value = (value << 8) | b;
        return value;
    }

    private static ulong DecodeUnsignedInteger(ReadOnlySpan<byte> data)
    {
        ulong value = 0;
        foreach (byte b in data) value = (value << 8) | b;
        return value;
    }

    private static byte[] EncodeOid(string oid)
    {
        var parts = oid.Split('.', StringSplitOptions.RemoveEmptyEntries).Select(uint.Parse).ToArray();
        if (parts.Length < 2) throw new ArgumentException("Invalid OID", nameof(oid));

        var bytes = new List<byte> { checked((byte)(parts[0] * 40 + parts[1])) };
        Span<byte> tmp = stackalloc byte[5];
        for (int i = 2; i < parts.Length; i++)
        {
            uint value = parts[i];
            int pos = tmp.Length;
            tmp[--pos] = (byte)(value & 0x7F);
            value >>= 7;
            while (value > 0)
            {
                tmp[--pos] = (byte)((value & 0x7F) | 0x80);
                value >>= 7;
            }
            for (; pos < tmp.Length; pos++) bytes.Add(tmp[pos]);
        }
        return bytes.ToArray();
    }

    private static string DecodeOid(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return "";
        var parts = new List<uint>();
        uint first = data[0];
        parts.Add(first < 80 ? first / 40 : 2);
        parts.Add(first < 80 ? first % 40 : first - 80);

        uint value = 0;
        for (int i = 1; i < data.Length; i++)
        {
            value = (value << 7) | (uint)(data[i] & 0x7F);
            if ((data[i] & 0x80) == 0)
            {
                parts.Add(value);
                value = 0;
            }
        }
        return string.Join(".", parts);
    }

    private static byte[] Tlv(byte tag, byte[] content)
    {
        var length = EncodeLength(content.Length);
        var output = new byte[1 + length.Length + content.Length];
        output[0] = tag;
        Buffer.BlockCopy(length, 0, output, 1, length.Length);
        Buffer.BlockCopy(content, 0, output, 1 + length.Length, content.Length);
        return output;
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80) return new[] { (byte)length };
        if (length <= 0xFF) return new[] { (byte)0x81, (byte)length };
        if (length <= 0xFFFF) return new[] { (byte)0x82, (byte)(length >> 8), (byte)length };
        return new[] { (byte)0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length };
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        int length = arrays.Sum(a => a.Length);
        var result = new byte[length];
        int offset = 0;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }
        return result;
    }

    private ref struct BerReader
    {
        private ReadOnlySpan<byte> _buffer;
        private int _offset;

        public BerReader(ReadOnlySpan<byte> buffer)
        {
            _buffer = buffer;
            _offset = 0;
        }

        public int ReadInteger()
        {
            var value = ReadExpected(0x02);
            return checked((int)DecodeSignedInteger(value));
        }

        public ReadOnlySpan<byte> ReadExpected(byte expectedTag)
        {
            var value = ReadAny(out byte tag);
            if (tag != expectedTag)
                throw new InvalidDataException($"Expected BER tag 0x{expectedTag:X2}, got 0x{tag:X2}");
            return value;
        }

        public ReadOnlySpan<byte> ReadAny(out byte tag)
        {
            if (_offset >= _buffer.Length) throw new EndOfStreamException();
            tag = _buffer[_offset++];
            int length = ReadLength();
            if (length < 0 || _offset + length > _buffer.Length) throw new InvalidDataException("Invalid BER length");
            var value = _buffer.Slice(_offset, length);
            _offset += length;
            return value;
        }

        private int ReadLength()
        {
            if (_offset >= _buffer.Length) throw new EndOfStreamException();
            int first = _buffer[_offset++];
            if ((first & 0x80) == 0) return first;
            int count = first & 0x7F;
            if (count is < 1 or > 4 || _offset + count > _buffer.Length) throw new InvalidDataException("Invalid BER length bytes");
            int length = 0;
            for (int i = 0; i < count; i++) length = (length << 8) | _buffer[_offset++];
            return length;
        }
    }
}
