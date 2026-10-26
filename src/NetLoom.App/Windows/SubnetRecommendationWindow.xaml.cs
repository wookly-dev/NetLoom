using System.Windows;
using System.Windows.Input;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class SubnetRecommendationWindow : Window
{
    private readonly IReadOnlyList<SubnetRecommendation> _recommendations;
    public string TargetExpression { get; private set; } = "";

    public SubnetRecommendationWindow(AdapterInfo adapter, IReadOnlyList<SubnetRecommendation> recommendations)
    {
        InitializeComponent();
        _recommendations = recommendations;
        RecommendationList.ItemsSource = _recommendations;
        AdapterText.Text = string.IsNullOrWhiteSpace(adapter.GatewayAddress)
            ? $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength}"
            : $"{adapter.Name} · {adapter.Address}/{adapter.PrefixLength} · GW {adapter.GatewayAddress}";

        int directOrActive = _recommendations.Count(x =>
            string.Equals(x.Source, "직접 연결", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(x.Source, "활성 인터페이스", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(x.Source, "다른 활성 어댑터", StringComparison.OrdinalIgnoreCase));
        int routed = _recommendations.Count(x => string.Equals(x.Source, "라우팅 감지", StringComparison.OrdinalIgnoreCase));
        int nested = _recommendations.Count(x => x.Source.StartsWith("SNMP", StringComparison.OrdinalIgnoreCase));
        int unresolved = _recommendations.Count(x => x.Reachability.Contains("미확인", StringComparison.OrdinalIgnoreCase));
        RecommendationSummaryText.Text = $"현재 추천 {_recommendations.Count:N0}개 · 직접/활성 {directOrActive:N0} · 명시 라우팅 {routed:N0} · SNMP 하위 {nested:N0}" +
                                         (unresolved > 0 ? $" · 경로 미확인 {unresolved:N0}" : "");
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _recommendations) item.IsSelected = true;
        RecommendationList.Items.Refresh();
    }

    private void SelectReachable_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _recommendations)
        {
            item.IsSelected = string.Equals(item.Source, "직접 연결", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(item.Reachability, "라우팅 확인", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(item.Reachability, "현재 감사 범위", StringComparison.OrdinalIgnoreCase);
        }
        RecommendationList.Items.Refresh();
    }

    private void SelectDirect_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _recommendations)
            item.IsSelected = string.Equals(item.Source, "직접 연결", StringComparison.OrdinalIgnoreCase);
        RecommendationList.Items.Refresh();
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        var selected = _recommendations.Where(x => x.IsSelected).Select(x => x.Cidr).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (selected.Length == 0)
        {
            ThemedMessageBox.Show("적용할 감사 대역을 하나 이상 선택하세요.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        TargetExpression = string.Join(Environment.NewLine, selected);
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void Close_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
