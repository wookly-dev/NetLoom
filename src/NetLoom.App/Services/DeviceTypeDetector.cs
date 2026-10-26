using System.Net;
using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class DeviceTypeDetector
{
    public static DeviceType Detect(IPAddress ip, string hostName, IReadOnlyCollection<int> openPorts, string gatewayAddress) =>
        Analyze(ip, hostName, openPorts, gatewayAddress, null).Type;

    public static DeviceClassification Analyze(
        IPAddress ip,
        string hostName,
        IReadOnlyCollection<int> openPorts,
        string gatewayAddress,
        SmbShareAuditResult? shareAudit,
        IppPrinterInfo? ippInfo = null,
        SnmpDeviceInfo? snmpInfo = null)
    {
        if (!string.IsNullOrWhiteSpace(gatewayAddress) &&
            string.Equals(ip.ToString(), gatewayAddress, StringComparison.OrdinalIgnoreCase))
        {
            return new DeviceClassification
            {
                Type = DeviceType.Router,
                Confidence = 100,
                Evidence = new[] { "현재 어댑터의 기본 게이트웨이 주소와 일치" }
            };
        }

        string host = (hostName ?? string.Empty).ToLowerInvariant();
        var ports = openPorts is HashSet<int> set ? set : new HashSet<int>(openPorts);
        var scores = new Dictionary<DeviceType, int>();
        var evidence = new Dictionary<DeviceType, List<string>>();

        void Add(DeviceType type, int score, string reason)
        {
            scores[type] = scores.TryGetValue(type, out int current) ? current + score : score;
            if (!evidence.TryGetValue(type, out var list))
            {
                list = new List<string>();
                evidence[type] = list;
            }
            if (!list.Any(existing => string.Equals(existing, reason, StringComparison.OrdinalIgnoreCase)))
                list.Add(reason);
        }

        void HostHint(DeviceType type, int score, string label, params string[] patterns)
        {
            if (ContainsAny(host, patterns))
                Add(type, score, $"호스트명 패턴: {label}");
        }

        // Hostname is the strongest non-invasive signal available without SNMP/LLDP or banner login.
        HostHint(DeviceType.Firewall, 120, "Firewall/VPN", "fortigate", "fortinet", "pfsense", "opnsense", "sophos", "sonicwall", "watchguard", "firewall", "-fw", "fw-");
        HostHint(DeviceType.WifiExtender, 120, "Wi-Fi Extender/Mesh", "extender", "range-extender", "rangeextender", "repeater", "wifi-repeater", "mesh-node", "meshnode", "mesh-point", "meshpoint", "deco-", "eero-", "orbi-", "velop-");
        HostHint(DeviceType.AccessPoint, 120, "Access Point", "accesspoint", "access-point", "unifi-ap", "uap-", "aruba-ap", "ruckus", "wifi-ap", "wlan-ap", "-ap", "ap-");
        HostHint(DeviceType.Hub, 120, "Ethernet Hub", "ethernet-hub", "network-hub", "net-hub", "hub-", "-hub");
        HostHint(DeviceType.Switch, 120, "Switch", "switch", "catalyst", "procurve", "aruba-sw", "core-sw", "edge-sw", "managed-sw", "-sw", "sw-");
        HostHint(DeviceType.Router, 120, "Router/Gateway", "router", "gateway", "mikrotik", "edgerouter", "edge-router", "-gw", "gw-");

        HostHint(DeviceType.Nas, 130, "NAS vendor/model", "synology", "diskstation", "rackstation", "qnap", "terramaster", "asustor", "readynas", "buffalo-nas", "nas-", "-nas", "nas.");
        HostHint(DeviceType.Hypervisor, 130, "Hypervisor", "esxi", "vmware", "vcenter", "hyper-v", "hyperv", "proxmox", "xenserver");
        HostHint(DeviceType.Printer, 130, "Printer vendor/model", "printer", "laserjet", "officejet", "deskjet", "designjet", "pagewide", "smart-tank", "plotter", "mfp", "epson", "brother", "xerox", "workcentre", "versalink", "altalink", "ricoh", "bizhub", "kyocera", "ecosys", "taskalfa", "canon-pr", "imageclass", "imagerunner", "imagepress", "lexmark", "oki-pr", "prn-", "-prn", "lbp-");
        HostHint(DeviceType.VoipPhone, 120, "IP Phone/VoIP", "ipphone", "ip-phone", "voip", "yealink", "grandstream", "avaya", "mitel", "polycom", "cisco-phone", "sip-phone", "phone-", "-phone");
        HostHint(DeviceType.Camera, 120, "Camera/NVR", "camera", "cctv", "cam-", "-cam", "nvr", "dvr", "hikvision", "dahua");
        HostHint(DeviceType.Ups, 120, "UPS", "apc-ups", "eaton-ups", "smartups", "ups-", "-ups");
        HostHint(DeviceType.Mobile, 110, "Mobile", "iphone", "ipad", "android", "galaxy", "pixel", "mobile");
        HostHint(DeviceType.Server, 115, "Server", "server", "srv-", "-srv", "sql-", "web-", "app-", "db-", "dc-", "domaincontroller");

        // Protocol-backed identity has higher confidence than hostname/port heuristics.
        if (ippInfo?.Success == true)
        {
            string ippIdentity = !string.IsNullOrWhiteSpace(ippInfo.MakeAndModel)
                ? ippInfo.MakeAndModel
                : !string.IsNullOrWhiteSpace(ippInfo.PrinterName) ? ippInfo.PrinterName : "IPP printer";
            Add(DeviceType.Printer, 260, $"IPP Get-Printer-Attributes 확인: {ippIdentity}");
            if (!string.IsNullOrWhiteSpace(ippInfo.Location))
                Add(DeviceType.Printer, 18, $"IPP 위치 정보: {ippInfo.Location}");
        }

        if (snmpInfo?.Success == true)
        {
            string snmpText = $"{snmpInfo.SysDescr} {snmpInfo.SysName} {snmpInfo.SysObjectId}".ToLowerInvariant();
            string identity = !string.IsNullOrWhiteSpace(snmpInfo.SysDescr) ? snmpInfo.SysDescr : snmpInfo.SysName;

            void SnmpHint(DeviceType type, int score, string label, params string[] patterns)
            {
                if (ContainsAny(snmpText, patterns))
                    Add(type, score, $"SNMP 식별: {label}{(string.IsNullOrWhiteSpace(identity) ? string.Empty : $" · {identity}")}");
            }

            SnmpHint(DeviceType.Nas, 235, "NAS", "synology", "diskstation", "rackstation", "qnap", "nas", "storage server", "terramaster", "asustor", "readynas");
            SnmpHint(DeviceType.Printer, 235, "Printer/MFP", "printer", "laserjet", "officejet", "deskjet", "xerox", "ricoh", "kyocera", "epson", "brother", "lexmark", "imageclass", "imagerunner", "bizhub", "oki");
            SnmpHint(DeviceType.Hypervisor, 230, "Hypervisor", "vmware", "esxi", "vcenter", "proxmox", "xenserver", "hyper-v");
            SnmpHint(DeviceType.Switch, 225, "Switch", "switch", "catalyst", "procurve", "aruba", "managed ethernet", "ethernet switch");
            SnmpHint(DeviceType.AccessPoint, 225, "Access Point", "access point", "wireless ap", "unifi ap", "ruckus", "wlan ap");
            SnmpHint(DeviceType.WifiExtender, 225, "Wi-Fi Extender/Mesh", "extender", "repeater", "mesh point", "mesh node");
            SnmpHint(DeviceType.Router, 220, "Router/Gateway", "router", "gateway", "mikrotik", "edgerouter");
            SnmpHint(DeviceType.Firewall, 230, "Firewall", "firewall", "fortigate", "fortinet", "pfsense", "opnsense", "sophos", "sonicwall");
            SnmpHint(DeviceType.Ups, 230, "UPS", "ups", "smart-ups", "apc", "eaton");
            SnmpHint(DeviceType.Server, 175, "Server OS", "windows server", "linux", "ubuntu", "centos", "red hat", "debian");

            if (string.Equals(snmpInfo.IpForwarding, "1", StringComparison.Ordinal))
                Add(DeviceType.Router, 110, "SNMP ipForwarding=forwarding · IPv4 라우팅 기능 확인");
        }

        // Printer: 9100/515 are much stronger than 631 alone. TCP/631 can also be a CUPS print server.
        if (ports.Contains(9100)) Add(DeviceType.Printer, 90, "TCP/9100 RAW Printing (JetDirect) 열림");
        if (ports.Contains(515)) Add(DeviceType.Printer, 70, "TCP/515 LPD 열림");
        if (ports.Contains(631)) Add(DeviceType.Printer, 38, "TCP/631 IPP 열림");
        if (ports.Contains(9100) && (ports.Contains(515) || ports.Contains(631)))
            Add(DeviceType.Printer, 25, "복수의 프린팅 서비스가 동시에 감지됨");

        // NAS/storage: require a storage-specific service or multiple storage signals.
        bool smb = ports.Contains(445) || ports.Contains(139) || shareAudit?.SmbDetected == true;
        bool dsm = ports.Contains(5000) || ports.Contains(5001);
        if (dsm) Add(DeviceType.Nas, 52, "TCP/5000 또는 5001 NAS 관리 UI 계열 감지");
        if (ports.Contains(6690)) Add(DeviceType.Nas, 72, "TCP/6690 Synology Drive 계열 서비스 감지");
        if (ports.Contains(6281)) Add(DeviceType.Nas, 58, "TCP/6281 백업 저장소 계열 서비스 감지");
        if (ports.Contains(3260)) Add(DeviceType.Nas, 66, "TCP/3260 iSCSI Target 감지");
        if (ports.Contains(2049)) Add(DeviceType.Nas, 34, "TCP/2049 NFS 감지");
        if (ports.Contains(873)) Add(DeviceType.Nas, 28, "TCP/873 rsync 감지");
        if (ports.Contains(548)) Add(DeviceType.Nas, 34, "TCP/548 AFP 감지");
        if (smb && dsm) Add(DeviceType.Nas, 32, "SMB와 NAS 관리 포트가 함께 감지됨");
        if (smb && (ports.Contains(2049) || ports.Contains(3260) || ports.Contains(873) || ports.Contains(548)))
            Add(DeviceType.Nas, 28, "SMB와 스토리지 프로토콜이 함께 감지됨");

        var shareNames = (shareAudit?.EnumeratedShares ?? Array.Empty<string>())
            .Select(s => (s ?? string.Empty).Trim().ToLowerInvariant())
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (shareNames.Any(s => s is "sysvol" or "netlogon"))
            Add(DeviceType.Server, 110, "도메인 서버 공유(SYSVOL/NETLOGON) 감지");

        string[] nasShareHints =
        {
            "homes", "photo", "photos", "video", "videos", "music", "surveillance", "web", "docker",
            "activebackupforbusiness", "netbackup", "usbshare", "multimedia", "recordings", "backup"
        };
        int nasShareHits = shareNames.Count(s => nasShareHints.Any(hint => string.Equals(hint, s, StringComparison.OrdinalIgnoreCase)));
        if (nasShareHits >= 2)
            Add(DeviceType.Nas, 48, $"NAS형 공유폴더 패턴 {nasShareHits}개 감지");
        else if (nasShareHits == 1 && (dsm || ports.Contains(2049) || ports.Contains(3260)))
            Add(DeviceType.Nas, 22, "NAS형 공유폴더와 스토리지 서비스가 함께 감지됨");

        // Hypervisor and server services.
        if (ports.Contains(902) || ports.Contains(903)) Add(DeviceType.Hypervisor, 105, "VMware 호스트 서비스 TCP/902 또는 903 감지");
        if (ports.Contains(8006)) Add(DeviceType.Hypervisor, 105, "Proxmox 관리 포트 TCP/8006 감지");
        if (ports.Contains(9443)) Add(DeviceType.Hypervisor, 48, "가상화/관리 계열 TCP/9443 감지");

        int[] databasePorts = { 1433, 1521, 3306, 5432, 6379, 9200, 27017 };
        int dbHits = databasePorts.Count(ports.Contains);
        if (dbHits > 0) Add(DeviceType.Server, 82 + Math.Min(24, (dbHits - 1) * 12), $"DB 서비스 포트 {dbHits}개 감지");
        if (ports.Contains(22) && HasAny(ports, 80, 443, 8080, 8443)) Add(DeviceType.Server, 48, "SSH + Web 관리/서비스 조합");
        if (ports.Contains(25) || ports.Contains(110) || ports.Contains(143) || ports.Contains(465) || ports.Contains(587) || ports.Contains(993) || ports.Contains(995))
            Add(DeviceType.Server, 46, "메일 서버 계열 포트 감지");
        if (ports.Contains(389)) Add(DeviceType.Server, 52, "LDAP 디렉터리 서비스 감지");
        if (ports.Contains(5985) || ports.Contains(5986)) Add(DeviceType.Server, 28, "WinRM 원격관리 서비스 감지");

        // If IPP is the only printer clue and the host also looks like a server, bias toward print server rather than printer.
        if (ports.Contains(631) && !ports.Contains(9100) && !ports.Contains(515) &&
            (ports.Contains(22) || dbHits > 0 || ports.Contains(5985) || ports.Contains(5986)))
        {
            Add(DeviceType.Server, 48, "IPP가 있으나 서버 관리 포트도 함께 감지되어 Print Server 가능성");
        }

        // Other endpoint signatures.
        if (HasAny(ports, 5060, 5061, 2000, 2427, 2727, 4569)) Add(DeviceType.VoipPhone, 86, "VoIP/SIP 계열 서비스 감지");
        if (ports.Contains(554) || ports.Contains(8554)) Add(DeviceType.Camera, 82, "RTSP 영상 스트림 서비스 감지");
        if (ports.Contains(1883) || ports.Contains(8883)) Add(DeviceType.IoT, 68, "MQTT 서비스 감지");

        // Generic Windows endpoint. SMB alone is deliberately not considered NAS evidence.
        int windowsSignals = 0;
        if (ports.Contains(135)) windowsSignals++;
        if (ports.Contains(139)) windowsSignals++;
        if (ports.Contains(445)) windowsSignals++;
        if (ports.Contains(3389)) windowsSignals++;
        if (windowsSignals >= 2) Add(DeviceType.Pc, 42 + windowsSignals * 5, $"Windows endpoint 포트 {windowsSignals}개 감지");
        else if (windowsSignals == 1) Add(DeviceType.Pc, 24, "Windows endpoint 서비스 일부 감지");

        // A generic Telnet appliance is still a leaf, never a topology parent.
        if (ports.Contains(23)) Add(DeviceType.NetworkDevice, 28, "Telnet 기반 레거시 장비 가능성");

        if (scores.Count == 0)
            return new DeviceClassification { Type = DeviceType.Unknown, Confidence = 0, Evidence = Array.Empty<string>() };

        var ranked = scores.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key.ToString(), StringComparer.Ordinal).ToArray();
        var best = ranked[0];
        int second = ranked.Length > 1 ? ranked[1].Value : 0;

        // Keep weak single-port guesses as Unknown instead of over-classifying an audit asset.
        if (best.Value < 30)
        {
            return new DeviceClassification
            {
                Type = DeviceType.Unknown,
                Confidence = Math.Clamp(35 + best.Value / 2, 35, 55),
                Evidence = evidence.TryGetValue(best.Key, out var weakEvidence) ? weakEvidence.Take(3).ToArray() : Array.Empty<string>()
            };
        }

        int margin = Math.Max(0, best.Value - second);
        int confidence = Math.Clamp(48 + best.Value / 2 + margin / 5, 55, 99);

        return new DeviceClassification
        {
            Type = best.Key,
            Confidence = confidence,
            Evidence = evidence.TryGetValue(best.Key, out var bestEvidence)
                ? bestEvidence.Take(5).ToArray()
                : Array.Empty<string>()
        };
    }

    private static bool HasAny(HashSet<int> ports, params int[] candidates) => candidates.Any(ports.Contains);

    private static bool ContainsAny(string value, params string[] candidates) =>
        candidates.Any(candidate => value.Contains(candidate, StringComparison.OrdinalIgnoreCase));
}
