using System.Runtime.InteropServices;
using System.Text;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class WifiAuditService
{
    private const uint ErrorSuccess = 0;
    private const uint WlanAvailableNetworkConnected = 0x00000001;
    private const int WlanMaxNameLength = 256;
    private const int Dot11SsidMaxLength = 32;
    private const int WlanMaxPhyTypeNumber = 8;

    public static Task<WifiAuditResult> AuditAsync(AdapterInfo adapter, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Audit(adapter, cancellationToken), cancellationToken);
    }

    private static WifiAuditResult Audit(AdapterInfo adapter, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return Unsupported(adapter, "Wi-Fi 보안 점검은 Windows WLAN API에서 동작합니다.");
        }

        if (!adapter.IsWireless)
        {
            return Unsupported(adapter, "선택한 어댑터는 Wi-Fi 어댑터가 아닙니다.");
        }

        uint negotiatedVersion;
        IntPtr clientHandle;
        var openResult = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);
        if (openResult != ErrorSuccess)
            return Unsupported(adapter, $"Windows WLAN 서비스를 열 수 없습니다. 오류 코드 {openResult}");

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wlanInterface = FindInterface(clientHandle, adapter);
            if (wlanInterface is null)
                return Unsupported(adapter, "선택한 네트워크 어댑터와 일치하는 Windows WLAN 인터페이스를 찾지 못했습니다.");

            var guid = wlanInterface.Value.InterfaceGuid;

            // Ask Windows to refresh the visible network list. Failure is non-fatal because cached data may still exist.
            _ = WlanScan(clientHandle, ref guid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            for (var i = 0; i < 7; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(120);
            }

            var current = TryGetCurrentConnection(clientHandle, guid);
            var networks = GetAvailableNetworks(clientHandle, guid, current)
                .OrderByDescending(n => n.IsConnected)
                .ThenByDescending(n => n.SignalQuality)
                .ThenBy(n => n.Ssid, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            var findings = BuildFindings(networks, current);
            var status = current is null
                ? $"주변 Wi-Fi {networks.Length}개 감지 · 현재 연결 정보 없음"
                : $"현재 연결 {current.Ssid} · {current.Authentication} / {current.Cipher} · 주변 {networks.Length}개";

            return new WifiAuditResult
            {
                AuditedAt = DateTime.Now,
                AdapterName = adapter.Name,
                AdapterDescription = adapter.Description,
                InterfaceId = adapter.InterfaceId,
                Supported = true,
                StatusMessage = status,
                CurrentNetwork = current,
                Networks = networks,
                Findings = findings
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return Unsupported(adapter, $"Wi-Fi 보안 점검 중 오류가 발생했습니다. {ex.Message}");
        }
        finally
        {
            WlanCloseHandle(clientHandle, IntPtr.Zero);
        }
    }

    private static WifiAuditResult Unsupported(AdapterInfo adapter, string message) => new()
    {
        AuditedAt = DateTime.Now,
        AdapterName = adapter.Name,
        AdapterDescription = adapter.Description,
        InterfaceId = adapter.InterfaceId,
        Supported = false,
        StatusMessage = message
    };

    private static WLAN_INTERFACE_INFO? FindInterface(IntPtr clientHandle, AdapterInfo adapter)
    {
        IntPtr listPtr;
        var result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out listPtr);
        if (result != ErrorSuccess || listPtr == IntPtr.Zero)
            return null;

        try
        {
            int count = Marshal.ReadInt32(listPtr, 0);
            int itemSize = Marshal.SizeOf<WLAN_INTERFACE_INFO>();
            int offset = 8;
            var interfaces = new List<WLAN_INTERFACE_INFO>();

            for (int i = 0; i < count; i++)
            {
                var itemPtr = IntPtr.Add(listPtr, offset + i * itemSize);
                interfaces.Add(Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(itemPtr));
            }

            if (Guid.TryParse(adapter.InterfaceId, out var adapterGuid))
            {
                var exact = interfaces.FirstOrDefault(x => x.InterfaceGuid == adapterGuid);
                if (exact.InterfaceGuid != Guid.Empty)
                    return exact;
            }

            var byDescription = interfaces.FirstOrDefault(x =>
                (!string.IsNullOrWhiteSpace(adapter.Description) &&
                 x.InterfaceDescription.Contains(adapter.Description, StringComparison.CurrentCultureIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(adapter.Name) &&
                 x.InterfaceDescription.Contains(adapter.Name, StringComparison.CurrentCultureIgnoreCase)));

            return byDescription.InterfaceGuid == Guid.Empty ? null : byDescription;
        }
        finally
        {
            WlanFreeMemory(listPtr);
        }
    }

    private static WifiNetworkInfo? TryGetCurrentConnection(IntPtr clientHandle, Guid interfaceGuid)
    {
        IntPtr dataPtr = IntPtr.Zero;
        uint dataSize;
        WLAN_OPCODE_VALUE_TYPE opcodeType;
        var guid = interfaceGuid;
        var result = WlanQueryInterface(
            clientHandle,
            ref guid,
            WLAN_INTF_OPCODE.CurrentConnection,
            IntPtr.Zero,
            out dataSize,
            out dataPtr,
            out opcodeType);

        if (result != ErrorSuccess || dataPtr == IntPtr.Zero)
            return null;

        try
        {
            var attributes = Marshal.PtrToStructure<WLAN_CONNECTION_ATTRIBUTES>(dataPtr);
            if (attributes.InterfaceState != WLAN_INTERFACE_STATE.Connected)
                return null;

            var ssid = DecodeSsid(attributes.AssociationAttributes.Ssid);
            var authValue = (uint)attributes.SecurityAttributes.AuthAlgorithm;
            var cipherValue = (uint)attributes.SecurityAttributes.CipherAlgorithm;
            var security = EvaluateSecurity(attributes.SecurityAttributes.SecurityEnabled, authValue, cipherValue);

            return new WifiNetworkInfo
            {
                Ssid = string.IsNullOrWhiteSpace(ssid) ? "(숨김 SSID)" : ssid,
                ProfileName = attributes.ProfileName?.TrimEnd('\0') ?? "",
                Authentication = AuthName(authValue),
                Cipher = CipherName(cipherValue),
                SignalQuality = (int)Math.Clamp(attributes.AssociationAttributes.SignalQuality, 0u, 100u),
                SecurityEnabled = attributes.SecurityAttributes.SecurityEnabled,
                IsConnected = true,
                SecurityGrade = security.Grade,
                SecuritySummary = security.Summary
            };
        }
        finally
        {
            WlanFreeMemory(dataPtr);
        }
    }

    private static IReadOnlyList<WifiNetworkInfo> GetAvailableNetworks(
        IntPtr clientHandle,
        Guid interfaceGuid,
        WifiNetworkInfo? current)
    {
        IntPtr listPtr;
        var guid = interfaceGuid;
        var result = WlanGetAvailableNetworkList(clientHandle, ref guid, 0, IntPtr.Zero, out listPtr);
        if (result != ErrorSuccess || listPtr == IntPtr.Zero)
            return current is null ? Array.Empty<WifiNetworkInfo>() : new[] { current! };

        try
        {
            int count = Marshal.ReadInt32(listPtr, 0);
            int itemSize = Marshal.SizeOf<WLAN_AVAILABLE_NETWORK>();
            int offset = 8;
            var networks = new List<WifiNetworkInfo>(Math.Max(1, count));

            for (int i = 0; i < count; i++)
            {
                var itemPtr = IntPtr.Add(listPtr, offset + i * itemSize);
                var raw = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK>(itemPtr);
                var ssid = DecodeSsid(raw.Ssid);
                if (string.IsNullOrWhiteSpace(ssid)) ssid = "(숨김 SSID)";

                var authValue = (uint)raw.DefaultAuthAlgorithm;
                var cipherValue = (uint)raw.DefaultCipherAlgorithm;
                var security = EvaluateSecurity(raw.SecurityEnabled, authValue, cipherValue);
                bool connected = (raw.Flags & WlanAvailableNetworkConnected) != 0 ||
                                 (current is not null && string.Equals(current.Ssid, ssid, StringComparison.Ordinal));

                networks.Add(new WifiNetworkInfo
                {
                    Ssid = ssid,
                    ProfileName = raw.ProfileName?.TrimEnd('\0') ?? "",
                    Authentication = AuthName(authValue),
                    Cipher = CipherName(cipherValue),
                    SignalQuality = (int)Math.Clamp(raw.SignalQuality, 0u, 100u),
                    SecurityEnabled = raw.SecurityEnabled,
                    IsConnected = connected,
                    SecurityGrade = security.Grade,
                    SecuritySummary = security.Summary
                });
            }

            // Collapse repeated entries with the same SSID/security mode; retain the strongest sample.
            var collapsed = networks
                .GroupBy(n => $"{n.Ssid}\u001F{n.Authentication}\u001F{n.Cipher}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(n => n.IsConnected).ThenByDescending(n => n.SignalQuality).First())
                .ToList();

            if (current is not null && !collapsed.Any(n => n.IsConnected))
                collapsed.Insert(0, current);

            return collapsed;
        }
        finally
        {
            WlanFreeMemory(listPtr);
        }
    }

    private static IReadOnlyList<WifiAuditFinding> BuildFindings(
        IReadOnlyList<WifiNetworkInfo> networks,
        WifiNetworkInfo? current)
    {
        var findings = new List<WifiAuditFinding>();

        foreach (var network in networks)
        {
            if (network.SecurityGrade == "HIGH")
            {
                findings.Add(new WifiAuditFinding
                {
                    Severity = "HIGH",
                    Ssid = network.Ssid,
                    Title = network.IsConnected ? "현재 연결 Wi-Fi에 취약한 보안 방식 사용" : "주변 Wi-Fi에 취약한 보안 방식 감지",
                    Evidence = $"{network.Authentication} / {network.Cipher} · 신호 {network.SignalQuality}%",
                    Recommendation = network.SecurityEnabled
                        ? "WEP/구형 암호화를 비활성화하고 WPA2-AES 이상, 가능하면 WPA3로 전환"
                        : "Open Wi-Fi 사용을 중지하고 WPA2/WPA3 인증과 암호화를 적용"
                });
            }
            else if (network.SecurityGrade == "MEDIUM")
            {
                findings.Add(new WifiAuditFinding
                {
                    Severity = "MEDIUM",
                    Ssid = network.Ssid,
                    Title = network.IsConnected ? "현재 연결 Wi-Fi에 구형 보안 방식 사용" : "주변 Wi-Fi에 구형 보안 방식 감지",
                    Evidence = $"{network.Authentication} / {network.Cipher} · 신호 {network.SignalQuality}%",
                    Recommendation = "WPA/TKIP 호환 모드를 제거하고 WPA2-AES 또는 WPA3 전용 구성을 검토"
                });
            }
        }

        var mixedSecurity = networks
            .Where(n => n.Ssid != "(숨김 SSID)")
            .GroupBy(n => n.Ssid, StringComparer.Ordinal)
            .Where(g => g.Select(x => $"{x.Authentication}/{x.Cipher}").Distinct(StringComparer.OrdinalIgnoreCase).Count() > 1);

        foreach (var group in mixedSecurity)
        {
            findings.Add(new WifiAuditFinding
            {
                Severity = "INFO",
                Ssid = group.Key,
                Title = "동일 SSID에 서로 다른 보안 방식 감지",
                Evidence = string.Join(", ", group.Select(x => $"{x.Authentication}/{x.Cipher}").Distinct(StringComparer.OrdinalIgnoreCase)),
                Recommendation = "의도된 혼합 WPA2/WPA3 전환 모드인지, 비인가 AP 또는 잘못된 AP 설정이 아닌지 확인"
            });
        }

        if (current is not null && current.SignalQuality < 25)
        {
            findings.Add(new WifiAuditFinding
            {
                Severity = "INFO",
                Ssid = current.Ssid,
                Title = "현재 Wi-Fi 신호 품질 낮음",
                Evidence = $"신호 {current.SignalQuality}%",
                Recommendation = "AP 배치, 채널 혼잡 및 로밍 구성을 확인"
            });
        }

        return findings
            .OrderBy(f => WifiSeverityOrder(f.Severity))
            .ThenBy(f => f.Ssid, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static int WifiSeverityOrder(string severity) => severity switch
    {
        "HIGH" => 0,
        "MEDIUM" => 1,
        _ => 2
    };

    private static (string Grade, string Summary) EvaluateSecurity(bool securityEnabled, uint auth, uint cipher)
    {
        if (!securityEnabled || cipher == 0)
            return ("HIGH", "암호화되지 않은 Open Wi-Fi");

        if (auth == 2 || cipher is 1 or 5 or 0x101)
            return ("HIGH", "WEP 계열 보안 방식");

        if (auth is 3 or 4 or 5 || cipher == 2)
            return ("MEDIUM", "WPA/TKIP 등 구형 보안 방식");

        if (auth is 8 or 9 or 10 or 11)
            return ("OK", "WPA3/OWE 계열");

        if (auth is 6 or 7)
            return ("OK", "WPA2 계열");

        return ("INFO", "보안 방식 확인 필요");
    }

    private static string DecodeSsid(DOT11_SSID ssid)
    {
        if (ssid.SsidBytes is null || ssid.SsidLength == 0) return "";
        int length = (int)Math.Min((uint)ssid.SsidBytes.Length, ssid.SsidLength);
        return Encoding.UTF8.GetString(ssid.SsidBytes, 0, length).TrimEnd('\0');
    }

    private static string AuthName(uint value) => value switch
    {
        1 => "Open",
        2 => "Shared/WEP",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        5 => "WPA-None",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise",
        9 => "WPA3-SAE",
        10 => "OWE",
        11 => "WPA3-Enterprise-192",
        _ => $"Auth 0x{value:X}"
    };

    private static string CipherName(uint value) => value switch
    {
        0 => "None",
        1 => "WEP40",
        2 => "TKIP",
        4 => "AES/CCMP",
        5 => "WEP104",
        6 => "BIP",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        11 => "BIP-GMAC-128",
        12 => "BIP-GMAC-256",
        13 => "BIP-CMAC-256",
        0x100 => "Use Group",
        0x101 => "WEP",
        _ => $"Cipher 0x{value:X}"
    };

    [DllImport("wlanapi.dll")]
    private static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr clientHandle);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanEnumInterfaces(IntPtr clientHandle, IntPtr reserved, out IntPtr interfaceList);

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr memory);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanScan(IntPtr clientHandle, ref Guid interfaceGuid, IntPtr dot11Ssid, IntPtr ieData, IntPtr reserved);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanGetAvailableNetworkList(IntPtr clientHandle, ref Guid interfaceGuid, uint flags, IntPtr reserved, out IntPtr availableNetworkList);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanQueryInterface(
        IntPtr clientHandle,
        ref Guid interfaceGuid,
        WLAN_INTF_OPCODE opcode,
        IntPtr reserved,
        out uint dataSize,
        out IntPtr data,
        out WLAN_OPCODE_VALUE_TYPE opcodeValueType);

    private enum WLAN_INTF_OPCODE
    {
        CurrentConnection = 7
    }

    private enum WLAN_OPCODE_VALUE_TYPE
    {
        QueryOnly = 0,
        SetByGroupPolicy = 1,
        SetByUser = 2,
        Invalid = 3
    }

    private enum WLAN_INTERFACE_STATE
    {
        NotReady = 0,
        Connected = 1,
        AdHocNetworkFormed = 2,
        Disconnecting = 3,
        Disconnected = 4,
        Associating = 5,
        Discovering = 6,
        Authenticating = 7
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WlanMaxNameLength)]
        public string InterfaceDescription;
        public WLAN_INTERFACE_STATE InterfaceState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DOT11_SSID
    {
        public uint SsidLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Dot11SsidMaxLength)]
        public byte[] SsidBytes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_AVAILABLE_NETWORK
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WlanMaxNameLength)]
        public string ProfileName;
        public DOT11_SSID Ssid;
        public uint BssType;
        public uint NumberOfBssids;
        [MarshalAs(UnmanagedType.Bool)] public bool NetworkConnectable;
        public uint NotConnectableReason;
        public uint NumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = WlanMaxPhyTypeNumber)]
        public uint[] PhyTypes;
        [MarshalAs(UnmanagedType.Bool)] public bool MorePhyTypes;
        public uint SignalQuality;
        [MarshalAs(UnmanagedType.Bool)] public bool SecurityEnabled;
        public uint DefaultAuthAlgorithm;
        public uint DefaultCipherAlgorithm;
        public uint Flags;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_CONNECTION_ATTRIBUTES
    {
        public WLAN_INTERFACE_STATE InterfaceState;
        public uint ConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = WlanMaxNameLength)]
        public string ProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES AssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES SecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_ASSOCIATION_ATTRIBUTES
    {
        public DOT11_SSID Ssid;
        public uint BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Bssid;
        public uint PhyType;
        public uint PhyIndex;
        public uint SignalQuality;
        public uint RxRate;
        public uint TxRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_SECURITY_ATTRIBUTES
    {
        [MarshalAs(UnmanagedType.Bool)] public bool SecurityEnabled;
        [MarshalAs(UnmanagedType.Bool)] public bool OneXEnabled;
        public uint AuthAlgorithm;
        public uint CipherAlgorithm;
    }
}
