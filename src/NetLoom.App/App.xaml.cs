using System.Windows;
using System.Windows.Threading;
using NetLoom.App.Services;
using NetLoom.App.Windows;

namespace NetLoom.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        base.OnStartup(e);
    }

    private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        string logPath = CrashLogService.Write("DispatcherUnhandledException", e.Exception);
        try
        {
            ThemedMessageBox.Show(
                $"처리 중 예외가 발생했습니다. 프로그램을 종료하지 않고 작업을 계속합니다.\n\n{e.Exception.Message}\n\n로그: {logPath}",
                "NetLoom",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
            MessageBox.Show(
                $"NetLoom 처리 오류\n\n{e.Exception.Message}\n\n로그: {logPath}",
                "NetLoom",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        e.Handled = true;
    }
}
