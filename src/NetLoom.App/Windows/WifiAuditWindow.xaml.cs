using System.Windows;
using System.Windows.Input;
using NetLoom.App.Models;

namespace NetLoom.App.Windows;

public partial class WifiAuditWindow : Window
{
    public WifiAuditResult Audit { get; }

    public WifiAuditWindow(WifiAuditResult audit)
    {
        InitializeComponent();
        Audit = audit;
        DataContext = this;
        NetworksGrid.ItemsSource = audit.Networks;
        FindingsGrid.ItemsSource = audit.Findings;

        AdapterText.Text = $"{audit.AdapterName} · {audit.AdapterDescription}";
        CurrentText.Text = audit.StatusMessage;
        NetworkCountText.Text = $"SSID {audit.Networks.Count:N0}개";
        FindingCountText.Text = $"HIGH {audit.HighCount:N0} · MED {audit.MediumCount:N0}";
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }
}
