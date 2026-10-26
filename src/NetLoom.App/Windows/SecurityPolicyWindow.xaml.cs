using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using NetLoom.App.Models;
using NetLoom.App.Services;

namespace NetLoom.App.Windows;

public partial class SecurityPolicyWindow : Window
{
    private readonly SecurityRelationshipAnalyzer _analyzer;

    public SecurityPolicyWindow(SecurityRelationshipAnalyzer analyzer)
    {
        InitializeComponent();
        _analyzer = analyzer;
        PolicyPathText.Text = $"정책 파일: {_analyzer.PolicyStoragePath}";
        IntelPathText.Text = $"CSV: {_analyzer.IntelligenceStoragePath} · 형식: cidr,country,asn,provider,classification";
        LoadPolicy();
        UpdateIntelStatus();
    }

    private void LoadPolicy()
    {
        var p = _analyzer.GetPolicySnapshot();
        TrustedInternalBox.Text = string.Join(Environment.NewLine, p.TrustedInternalAddresses);
        AllowedExternalBox.Text = string.Join(Environment.NewLine, p.AllowedExternalAddresses);
        AllowedDomainsBox.Text = string.Join(Environment.NewLine, p.AllowedDomains);
        AllowedServiceGroupsBox.Text = string.Join(Environment.NewLine, p.AllowedServiceGroups);
        AllowedPortsBox.Text = string.Join(",", p.AllowedExternalPorts);
        DnsMinQueriesBox.Text = p.DnsMinimumQueries.ToString(CultureInfo.InvariantCulture);
        DnsNxRatioBox.Text = p.DnsNxDomainRatioPercent.ToString(CultureInfo.InvariantCulture);
        DnsLongLengthBox.Text = p.DnsLongQueryLength.ToString(CultureInfo.InvariantCulture);
        DnsLongCountBox.Text = p.DnsLongQueryCount.ToString(CultureInfo.InvariantCulture);
        StatusText.Text = p.UpdatedUtc == default ? "아직 저장된 사용자 정책이 없습니다." : $"마지막 저장: {p.UpdatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        if (!TryInt(DnsMinQueriesBox.Text, 5, 10000, out int minQueries) ||
            !TryInt(DnsNxRatioBox.Text, 5, 100, out int nxRatio) ||
            !TryInt(DnsLongLengthBox.Text, 40, 253, out int longLength) ||
            !TryInt(DnsLongCountBox.Text, 1, 1000, out int longCount))
        {
            ThemedMessageBox.Show("DNS 임계값을 확인하세요.\n최소 질의 5~10000, NXDOMAIN 5~100%, 긴 질의 길이 40~253, 건수 1~1000 범위입니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var trustedEntries = SplitLines(TrustedInternalBox.Text);
        var externalEntries = SplitLines(AllowedExternalBox.Text);
        var invalidAddresses = trustedEntries.Concat(externalEntries)
            .Where(x => !SecurityPolicyService.IsValidAddressEntry(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (invalidAddresses.Length > 0)
        {
            ThemedMessageBox.Show($"IPv4 / CIDR 형식을 확인하세요: {string.Join(", ", invalidAddresses.Take(8))}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var invalidPorts = SplitTokens(AllowedPortsBox.Text).Where(x => !int.TryParse(x, out int p) || p is < 1 or > 65535).ToArray();
        if (invalidPorts.Length > 0)
        {
            ThemedMessageBox.Show($"허용 외부 포트 형식을 확인하세요: {string.Join(", ", invalidPorts.Take(8))}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var policy = new SecurityPolicyDocument
        {
            TrustedInternalAddresses = trustedEntries,
            AllowedExternalAddresses = externalEntries,
            AllowedDomains = SplitLines(AllowedDomainsBox.Text),
            AllowedServiceGroups = SplitLines(AllowedServiceGroupsBox.Text),
            AllowedExternalPorts = SplitTokens(AllowedPortsBox.Text).Select(int.Parse).Distinct().OrderBy(x => x).ToList(),
            DnsMinimumQueries = minQueries,
            DnsNxDomainRatioPercent = nxRatio,
            DnsLongQueryLength = longLength,
            DnsLongQueryCount = longCount
        };
        _analyzer.SavePolicy(policy);
        LoadPolicy();
        StatusText.Text = "정책을 저장하고 즉시 적용했습니다.";
    }

    private void ReloadPolicy_Click(object sender, RoutedEventArgs e)
    {
        _analyzer.ReloadPolicy();
        LoadPolicy();
        StatusText.Text = "디스크의 정책 파일을 다시 읽었습니다.";
    }

    private void ReloadIntel_Click(object sender, RoutedEventArgs e)
    {
        _analyzer.ReloadIntelligence();
        UpdateIntelStatus();
        StatusText.Text = "Offline intelligence CSV를 다시 읽었습니다.";
    }

    private void OpenIntel_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _analyzer.EnsureIntelligenceTemplate();
            _analyzer.ReloadIntelligence();
            UpdateIntelStatus();
            Process.Start(new ProcessStartInfo(_analyzer.IntelligenceStoragePath) { UseShellExecute = true });
            StatusText.Text = "CSV를 열었습니다. 수정 후 'CSV 다시 읽기'를 누르세요.";
        }
        catch (Exception ex)
        {
            ThemedMessageBox.Show($"External intelligence CSV를 열지 못했습니다.\n\n{ex.Message}", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UpdateIntelStatus() => IntelStatusText.Text = $"현재 로드된 CIDR 레코드 {_analyzer.IntelligenceRecordCount:N0}개 · 자동 인터넷 조회/다운로드 없음";

    private static List<string> SplitLines(string value) => (value ?? "")
        .Replace("\r", "\n")
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(x => !x.StartsWith('#'))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    private static IEnumerable<string> SplitTokens(string value) => (value ?? "")
        .Split(new[] { ',', ';', ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool TryInt(string value, int min, int max, out int result) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out result) && result >= min && result <= max;

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
