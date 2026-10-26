using NetLoom.App.Models;

namespace NetLoom.App.Services;

public static class CommonPortCatalog
{
    public static IReadOnlyList<CommonPortDefinition> All { get; } = new List<CommonPortDefinition>
    {
        new() { Port = 20, Service = "FTP-DATA", Category = "파일/전송", Description = "FTP 데이터 채널" },
        new() { Port = 21, Service = "FTP", Category = "파일/전송", Description = "FTP 제어 채널" },
        new() { Port = 22, Service = "SSH", Category = "원격관리", Description = "SSH / SFTP" },
        new() { Port = 23, Service = "TELNET", Category = "원격관리", Description = "Telnet 원격 접속" },
        new() { Port = 25, Service = "SMTP", Category = "메일", Description = "SMTP 메일 전송" },
        new() { Port = 53, Service = "DNS", Category = "네트워크", Description = "DNS TCP" },
        new() { Port = 80, Service = "HTTP", Category = "웹", Description = "웹 서비스" },
        new() { Port = 110, Service = "POP3", Category = "메일", Description = "POP3" },
        new() { Port = 111, Service = "RPCBIND", Category = "Unix/Linux", Description = "RPC portmapper" },
        new() { Port = 135, Service = "MSRPC", Category = "Windows", Description = "Microsoft RPC" },
        new() { Port = 139, Service = "NETBIOS", Category = "Windows", Description = "NetBIOS Session" },
        new() { Port = 143, Service = "IMAP", Category = "메일", Description = "IMAP" },
        new() { Port = 389, Service = "LDAP", Category = "인증/디렉터리", Description = "LDAP" },
        new() { Port = 443, Service = "HTTPS", Category = "웹", Description = "HTTPS" },
        new() { Port = 445, Service = "SMB", Category = "Windows", Description = "SMB / CIFS" },
        new() { Port = 465, Service = "SMTPS", Category = "메일", Description = "SMTP over TLS" },
        new() { Port = 515, Service = "LPD", Category = "프린터", Description = "Line Printer Daemon" },
        new() { Port = 548, Service = "AFP", Category = "NAS/스토리지", Description = "Apple Filing Protocol" },
        new() { Port = 587, Service = "SUBMISSION", Category = "메일", Description = "SMTP Submission" },
        new() { Port = 631, Service = "IPP", Category = "프린터", Description = "Internet Printing Protocol" },
        new() { Port = 993, Service = "IMAPS", Category = "메일", Description = "IMAP over TLS" },
        new() { Port = 995, Service = "POP3S", Category = "메일", Description = "POP3 over TLS" },
        new() { Port = 1433, Service = "MSSQL", Category = "데이터베이스", Description = "Microsoft SQL Server" },
        new() { Port = 1521, Service = "ORACLE", Category = "데이터베이스", Description = "Oracle Listener" },
        new() { Port = 1723, Service = "PPTP", Category = "VPN", Description = "PPTP VPN" },
        new() { Port = 1883, Service = "MQTT", Category = "IoT", Description = "MQTT" },
        new() { Port = 2000, Service = "SCCP", Category = "VoIP", Description = "Cisco Skinny / IP Phone" },
        new() { Port = 2049, Service = "NFS", Category = "파일/전송", Description = "NFS" },
        new() { Port = 2427, Service = "MGCP", Category = "VoIP", Description = "Media Gateway Control Protocol" },
        new() { Port = 2727, Service = "MGCP-CALL", Category = "VoIP", Description = "MGCP Call Agent" },
        new() { Port = 3306, Service = "MYSQL", Category = "데이터베이스", Description = "MySQL / MariaDB" },
        new() { Port = 3389, Service = "RDP", Category = "Windows", Description = "Remote Desktop" },
        new() { Port = 4569, Service = "IAX2", Category = "VoIP", Description = "Asterisk IAX2" },
        new() { Port = 5000, Service = "HTTP-5000", Category = "NAS/장비", Description = "NAS / 관리 UI에 자주 사용" },
        new() { Port = 5001, Service = "HTTPS-5001", Category = "NAS/장비", Description = "NAS HTTPS 관리 UI에 자주 사용" },
        new() { Port = 5060, Service = "SIP", Category = "VoIP", Description = "SIP signaling" },
        new() { Port = 5061, Service = "SIPS", Category = "VoIP", Description = "SIP over TLS" },
        new() { Port = 5432, Service = "POSTGRESQL", Category = "데이터베이스", Description = "PostgreSQL" },
        new() { Port = 902, Service = "VMWARE-AUTH", Category = "가상화", Description = "VMware host service" },
        new() { Port = 903, Service = "VMWARE-CONSOLE", Category = "가상화", Description = "VMware console service" },
        new() { Port = 554, Service = "RTSP", Category = "카메라", Description = "RTSP 영상 스트림" },
        new() { Port = 5900, Service = "VNC", Category = "원격관리", Description = "VNC" },
        new() { Port = 5985, Service = "WINRM", Category = "Windows", Description = "Windows Remote Management HTTP" },
        new() { Port = 5986, Service = "WINRM-TLS", Category = "Windows", Description = "Windows Remote Management HTTPS" },
        new() { Port = 6379, Service = "REDIS", Category = "데이터베이스", Description = "Redis" },
        new() { Port = 8080, Service = "HTTP-ALT", Category = "웹", Description = "대체 HTTP / 관리 UI" },
        new() { Port = 873, Service = "RSYNC", Category = "NAS/스토리지", Description = "rsync 파일 동기화" },
        new() { Port = 3260, Service = "ISCSI", Category = "NAS/스토리지", Description = "iSCSI Target" },
        new() { Port = 6281, Service = "BACKUP-6281", Category = "NAS/스토리지", Description = "NAS 백업 저장소 계열 서비스" },
        new() { Port = 6690, Service = "SYNC-6690", Category = "NAS/스토리지", Description = "NAS 동기화/Drive 계열 서비스" },
        new() { Port = 8006, Service = "PROXMOX", Category = "가상화", Description = "Proxmox VE 관리 UI" },
        new() { Port = 9443, Service = "MGMT-9443", Category = "가상화", Description = "가상화/관리 HTTPS 계열" },
        new() { Port = 8443, Service = "HTTPS-ALT", Category = "웹", Description = "대체 HTTPS / 관리 UI" },
        new() { Port = 8554, Service = "RTSP-ALT", Category = "카메라", Description = "대체 RTSP" },
        new() { Port = 8883, Service = "MQTT-TLS", Category = "IoT", Description = "MQTT over TLS" },
        new() { Port = 9100, Service = "JETDIRECT", Category = "프린터", Description = "RAW Printing / JetDirect" },
        new() { Port = 9200, Service = "ELASTIC", Category = "데이터베이스", Description = "Elasticsearch HTTP" },
        new() { Port = 27017, Service = "MONGODB", Category = "데이터베이스", Description = "MongoDB" }
    };

    public static IReadOnlyDictionary<string, int[]> Presets { get; } = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase)
    {
        ["감사 기본"] = new[] { 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443 },
        ["Windows"] = new[] { 135, 139, 445, 3389, 5985, 5986 },
        ["서버"] = new[] { 22, 25, 53, 80, 443, 1433, 1521, 3306, 5432, 6379, 9200, 27017 },
        ["네트워크 장비"] = new[] { 22, 23, 53, 80, 443, 8080, 8443 },
        ["NAS"] = new[] { 22, 80, 139, 443, 445, 548, 873, 2049, 3260, 5000, 5001, 6281, 6690, 8080 },
        ["프린터"] = new[] { 80, 443, 515, 631, 9100 },
        ["인터넷 전화/VoIP"] = new[] { 80, 443, 2000, 2427, 2727, 4569, 5060, 5061 },
        ["가상화"] = new[] { 22, 80, 443, 902, 903, 5985, 5986, 8006, 9443 },
        ["카메라/IoT"] = new[] { 80, 443, 554, 1883, 8080, 8554, 8883 },
        ["공유폴더/SMB"] = new[] { 135, 139, 445 }
    };
}
