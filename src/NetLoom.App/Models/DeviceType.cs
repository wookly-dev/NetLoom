namespace NetLoom.App.Models;

public enum DeviceType
{
    Unknown,
    Pc,
    Mobile,
    Router,
    Switch,
    Hub,
    AccessPoint,
    WifiExtender,
    Firewall,
    Nas,
    Server,
    Hypervisor,
    Printer,
    VoipPhone,
    Camera,
    Ups,
    IoT,
    NetworkDevice,
    Internet
}

public static class DeviceTypeExtensions
{
    public static string ToDisplayName(this DeviceType type) => type switch
    {
        DeviceType.Pc => "PC",
        DeviceType.Mobile => "모바일",
        DeviceType.Router => "라우터",
        DeviceType.Switch => "스위치",
        DeviceType.Hub => "허브",
        DeviceType.AccessPoint => "AP",
        DeviceType.WifiExtender => "AP/Extender",
        DeviceType.Firewall => "방화벽",
        DeviceType.Nas => "NAS",
        DeviceType.Server => "서버",
        DeviceType.Hypervisor => "가상화 호스트",
        DeviceType.Printer => "프린터",
        DeviceType.VoipPhone => "VoIP/전화",
        DeviceType.Camera => "카메라",
        DeviceType.Ups => "UPS",
        DeviceType.IoT => "IoT",
        DeviceType.NetworkDevice => "네트워크 장치",
        DeviceType.Internet => "Internet",
        _ => "기타 장치"
    };
}
