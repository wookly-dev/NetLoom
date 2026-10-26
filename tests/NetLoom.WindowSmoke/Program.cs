using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        // In-process control test using the actual app resources, no UI Automation or network I/O.
        var app = new NetLoom.App.App();
        app.InitializeComponent();
        var button = new Button { Style = (Style)app.FindResource("WindowMaximizeButton") };
        var panel = new StackPanel();
        panel.Children.Add(button);
        var host = new Window { Title = "NetLoom synthetic chrome test", Width = 320, Height = 160, Content = panel, ShowInTaskbar = false };
        int checks = 0;
        try
        {
            host.Show();
            foreach (var state in new[] { WindowState.Normal, WindowState.Maximized, WindowState.Normal })
            {
                host.WindowState = state;
                host.UpdateLayout();
                host.Dispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
                button.ApplyTemplate();
                var maximize = (FrameworkElement)button.Template.FindName("MaximizeGlyph", button);
                var restore = (FrameworkElement)button.Template.FindName("RestoreGlyph", button);
                bool expanded = state == WindowState.Maximized;
                if (maximize.Visibility != (expanded ? Visibility.Collapsed : Visibility.Visible)
                    || restore.Visibility != (expanded ? Visibility.Visible : Visibility.Collapsed))
                    throw new InvalidOperationException("Wrong maximize/restore glyph for " + state);
                checks++;
            }
            Console.WriteLine($"PASS: {checks} WPF shared-caption state transitions (normal/maximized/restored).");
            return 0;
        }
        finally { host.Close(); app.Shutdown(); }
    }
}
