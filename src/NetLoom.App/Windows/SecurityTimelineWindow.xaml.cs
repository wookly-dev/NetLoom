using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using NetLoom.App.Models;
using System.IO;

namespace NetLoom.App.Windows;

public partial class SecurityTimelineWindow : Window
{
    private readonly Func<IReadOnlyList<SecurityTimelineEntry>> _provider;
    private readonly Action<SecurityRelationshipSnapshot?> _applyReplay;
    private readonly Action _clear;
    public ObservableCollection<SecurityTimelineEntry> Entries { get; } = new();

    public SecurityTimelineWindow(Func<IReadOnlyList<SecurityTimelineEntry>> provider, Action<SecurityRelationshipSnapshot?> applyReplay, Action clear)
    {
        InitializeComponent();
        _provider = provider;
        _applyReplay = applyReplay;
        _clear = clear;
        DataContext = this;
        RefreshEntries(selectLatest: true);
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshEntries(selectLatest: false);

    private void RefreshEntries(bool selectLatest)
    {
        var selectedTime = (TimelineGrid.SelectedItem as SecurityTimelineEntry)?.TimestampUtc;
        Entries.Clear();
        foreach (var entry in _provider().OrderBy(e => e.TimestampUtc)) Entries.Add(entry);
        CountText.Text = $"{Entries.Count:N0} snapshots";
        if (Entries.Count == 0) return;
        SecurityTimelineEntry? select = selectLatest ? Entries[Entries.Count - 1] : selectedTime.HasValue ? Entries.OrderBy(x => Math.Abs((x.TimestampUtc - selectedTime.Value).Ticks)).FirstOrDefault() : null;
        if (select is not null)
        {
            TimelineGrid.SelectedItem = select;
            TimelineGrid.ScrollIntoView(select);
        }
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (TimelineGrid.SelectedItem is not SecurityTimelineEntry entry)
        {
            StatusText.Text = "재생할 시점을 선택하세요.";
            return;
        }
        _applyReplay(entry.Snapshot);
        StatusText.Text = $"관계도 재생 시점 적용: {entry.TimestampUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} · 실제 분석은 LIVE로 계속 누적됩니다.";
    }

    private void Live_Click(object sender, RoutedEventArgs e)
    {
        _applyReplay(null);
        StatusText.Text = "관계도를 LIVE 보안 분석으로 복귀했습니다.";
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        var answer = ThemedMessageBox.Show("현재 세션의 보안 타임라인 스냅샷을 모두 지우시겠습니까?\n\n보안 분석/Baseline/외부 이력 자체는 지워지지 않습니다.", "NetLoom · 보안 타임라인", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;
        _applyReplay(null);
        _clear();
        RefreshEntries(selectLatest: false);
        StatusText.Text = "타임라인만 초기화했습니다.";
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (Entries.Count == 0)
        {
            ThemedMessageBox.Show("저장할 타임라인이 없습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var dialog = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = $"NetLoom_SecurityTimeline_{DateTime.Now:yyyyMMdd_HHmmss}.csv" };
        if (dialog.ShowDialog(this) != true) return;
        using var writer = new StreamWriter(dialog.FileName, false, new UTF8Encoding(true));
        writer.WriteLine("time,high,medium,watch,dns_anomaly,beacon,lateral,baseline_anomaly,top_risk");
        foreach (var e2 in Entries)
            writer.WriteLine(string.Join(',', Csv(e2.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")), e2.HighCount, e2.MediumCount, e2.WatchCount, e2.DnsAnomalyCount, e2.BeaconCount, e2.LateralCount, e2.BaselineAnomalyCount, Csv(e2.TopRiskText)));
        StatusText.Text = $"CSV 저장 완료: {dialog.FileName}";
    }

    private static string Csv(string value) => NetLoom.App.Helpers.CsvHelper.Escape(value);

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2) WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
