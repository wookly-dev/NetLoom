using System.Net;
using System.Windows;
using System.Windows.Input;
using NetLoom.App.Helpers;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class RangePickerWindow : Window
{
    private readonly AdapterInfo? _adapter;
    public string TargetExpression { get; private set; }

    public RangePickerWindow(AdapterInfo? adapter, string currentExpression)
    {
        InitializeComponent();
        _adapter = adapter;
        TargetExpression = currentExpression?.Trim() ?? "";
        TargetTextBox.Text = TargetExpression;

        if (adapter is not null)
        {
            AdapterInfoText.Text = string.IsNullOrWhiteSpace(adapter.GatewayAddress)
                ? $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength}"
                : $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength} · GW {adapter.GatewayAddress}";
            StartIpTextBox.Text = adapter.Address;
            EndIpTextBox.Text = MakeLastHost(adapter.Address, 24);
        }
        else
        {
            AdapterInfoText.Text = "선택된 IPv4 어댑터가 없습니다.";
        }

        ValidateCurrent();
    }

    private void UseAdapterSubnet_Click(object sender, RoutedEventArgs e)
    {
        if (_adapter is null) return;
        TargetTextBox.Text = BuildNetworkCidr(_adapter.Address, _adapter.PrefixLength);
        ValidateCurrent();
    }

    private void UseSlash24_Click(object sender, RoutedEventArgs e)
    {
        if (_adapter is null) return;
        TargetTextBox.Text = BuildNetworkCidr(_adapter.Address, 24);
        ValidateCurrent();
    }

    private void UseSingle_Click(object sender, RoutedEventArgs e)
    {
        if (_adapter is null) return;
        TargetTextBox.Text = _adapter.Address;
        ValidateCurrent();
    }

    private void ApplyRange_Click(object sender, RoutedEventArgs e)
    {
        TargetTextBox.Text = $"{StartIpTextBox.Text.Trim()} - {EndIpTextBox.Text.Trim()}";
        ValidateCurrent();
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var target = ScanTargetParser.Parse(TargetTextBox.Text);
            TargetExpression = target.NormalizedExpression;
            DialogResult = true;
        }
        catch (Exception ex)
        {
            ValidationText.Text = ex.Message;
            ValidationText.Foreground = System.Windows.Media.Brushes.IndianRed;
        }
    }

    private void ValidateCurrent()
    {
        try
        {
            var target = ScanTargetParser.Parse(TargetTextBox.Text);
            ValidationText.Text = target.Groups.Count > 1
                ? $"감사 대역 {target.Groups.Count:N0}개 · 스캔 대상 {target.Hosts.Count:N0}개 · {(target.IsPrivateOrLocal ? "사설/로컬 범위" : "공인 대역 포함")}"
                : $"스캔 대상 {target.Hosts.Count:N0}개 · {(target.IsPrivateOrLocal ? "사설/로컬 범위" : "공인 대역 포함")}";
            ValidationText.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(207, 194, 138));
        }
        catch (Exception ex)
        {
            ValidationText.Text = ex.Message;
            ValidationText.Foreground = System.Windows.Media.Brushes.IndianRed;
        }
    }

    private static string BuildNetworkCidr(string address, int prefixLength)
    {
        var ip = IPAddress.Parse(address);
        var b = ip.GetAddressBytes();
        uint value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        uint network = value & mask;
        return $"{(network >> 24) & 255}.{(network >> 16) & 255}.{(network >> 8) & 255}.{network & 255}/{prefixLength}";
    }

    private static string MakeLastHost(string address, int prefixLength)
    {
        var ip = IPAddress.Parse(address);
        var b = ip.GetAddressBytes();
        uint value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        uint network = value & mask;
        long total = 1L << (32 - prefixLength);
        uint last = prefixLength >= 31 ? network + (uint)total - 1 : network + (uint)total - 2;
        return $"{(last >> 24) & 255}.{(last >> 16) & 255}.{(last >> 8) & 255}.{last & 255}";
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void Close_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
