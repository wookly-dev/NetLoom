using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NetLoom.App.Models;

public sealed class MatrixNode : INotifyPropertyChanged
{
    private ScanNodeState _state = ScanNodeState.Pending;
    private DeviceType _deviceType = DeviceType.Unknown;
    private string _hostName = "";
    private string _openPorts = "";
    private string _shareAuditSummary = "";
    private bool _hasGuestShareExposure;
    private long? _roundTripMs;
    private ScanResult? _result;

    public string IpAddress { get; init; } = "";
    public string AddressLabel { get; init; } = "";
    public string GroupLabel { get; init; } = "";
    public string GroupExpression { get; init; } = "";

    public ScanResult? Result
    {
        get => _result;
        private set
        {
            if (ReferenceEquals(_result, value)) return;
            _result = value;
            OnPropertyChanged();
        }
    }

    public ScanNodeState State
    {
        get => _state;
        set
        {
            if (_state == value) return;
            _state = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(StateText));
        }
    }

    public DeviceType DeviceType
    {
        get => _deviceType;
        set
        {
            if (_deviceType == value) return;
            _deviceType = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DeviceLabel));
        }
    }

    public string HostName
    {
        get => _hostName;
        set { if (_hostName == value) return; _hostName = value; OnPropertyChanged(); }
    }

    public string OpenPorts
    {
        get => _openPorts;
        set { if (_openPorts == value) return; _openPorts = value; OnPropertyChanged(); }
    }

    public string ShareAuditSummary
    {
        get => _shareAuditSummary;
        set { if (_shareAuditSummary == value) return; _shareAuditSummary = value; OnPropertyChanged(); }
    }

    public bool HasGuestShareExposure
    {
        get => _hasGuestShareExposure;
        set { if (_hasGuestShareExposure == value) return; _hasGuestShareExposure = value; OnPropertyChanged(); }
    }

    public long? RoundTripMs
    {
        get => _roundTripMs;
        set { if (_roundTripMs == value) return; _roundTripMs = value; OnPropertyChanged(); OnPropertyChanged(nameof(RoundTripDisplay)); }
    }

    public string DeviceLabel => DeviceType.ToDisplayName();
    public string RoundTripDisplay => RoundTripMs.HasValue ? $"{RoundTripMs.Value} ms" : "-";
    public string StateText => State switch
    {
        ScanNodeState.Pending => "대기",
        ScanNodeState.Scanning => "스캔 중",
        ScanNodeState.Online => "ONLINE",
        ScanNodeState.Offline => "OFFLINE",
        _ => "-"
    };

    public void Apply(ScanResult result)
    {
        Result = result;
        State = result.IsOnline ? ScanNodeState.Online : ScanNodeState.Offline;
        DeviceType = result.DeviceType;
        HostName = result.HostName;
        OpenPorts = result.OpenPorts;
        ShareAuditSummary = result.ShareAuditSummary;
        HasGuestShareExposure = result.HasGuestShareExposure;
        RoundTripMs = result.RoundTripMs;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
