using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace NetLoom.App.Windows;

public partial class ThemedMessageBox : Window
{
    private readonly MessageBoxButton _buttons;
    public MessageBoxResult Result { get; private set; } = MessageBoxResult.None;

    private ThemedMessageBox(string message, string caption, MessageBoxButton buttons, MessageBoxImage image)
    {
        InitializeComponent();
        _buttons = buttons;
        CaptionText.Text = string.IsNullOrWhiteSpace(caption) ? "NetLoom" : caption;
        MessageText.Text = message ?? string.Empty;
        ApplyImage(image);
        BuildButtons(buttons);
    }

    public static MessageBoxResult Show(string message, string caption, MessageBoxButton buttons, MessageBoxImage image)
    {
        var dialog = new ThemedMessageBox(message, caption, buttons, image);
        var owner = Application.Current?.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive && w != dialog)
                    ?? Application.Current?.MainWindow;
        if (owner is not null && owner != dialog)
            dialog.Owner = owner;
        dialog.ShowDialog();
        return dialog.Result;
    }

    public static MessageBoxResult Show(string message, string caption = "NetLoom") =>
        Show(message, caption, MessageBoxButton.OK, MessageBoxImage.Information);

    private void ApplyImage(MessageBoxImage image)
    {
        switch (image)
        {
            case MessageBoxImage.Warning:
                IconText.Text = "!";
                IconText.Foreground = new SolidColorBrush(Color.FromRgb(250, 216, 59));
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(43, 38, 18));
                IconBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(108, 91, 28));
                break;
            case MessageBoxImage.Error:
                IconText.Text = "×";
                IconText.Foreground = new SolidColorBrush(Color.FromRgb(255, 115, 115));
                IconBadge.Background = new SolidColorBrush(Color.FromRgb(48, 24, 24));
                IconBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(121, 53, 53));
                break;
            case MessageBoxImage.Question:
                IconText.Text = "?";
                IconText.Foreground = new SolidColorBrush(Color.FromRgb(250, 216, 59));
                break;
            default:
                IconText.Text = "i";
                IconText.Foreground = new SolidColorBrush(Color.FromRgb(250, 216, 59));
                break;
        }
    }

    private void BuildButtons(MessageBoxButton buttons)
    {
        switch (buttons)
        {
            case MessageBoxButton.OKCancel:
                AddButton("취소", MessageBoxResult.Cancel, false, true);
                AddButton("확인", MessageBoxResult.OK, true, false);
                break;
            case MessageBoxButton.YesNo:
                AddButton("아니요", MessageBoxResult.No, false, true);
                AddButton("예", MessageBoxResult.Yes, true, false);
                break;
            case MessageBoxButton.YesNoCancel:
                AddButton("취소", MessageBoxResult.Cancel, false, true);
                AddButton("아니요", MessageBoxResult.No, false, false);
                AddButton("예", MessageBoxResult.Yes, true, false);
                break;
            default:
                AddButton("확인", MessageBoxResult.OK, true, true);
                break;
        }
    }

    private void AddButton(string label, MessageBoxResult result, bool isDefault, bool isCancel)
    {
        var button = new Button
        {
            Content = label,
            Style = (Style)FindResource("DialogButton"),
            IsDefault = isDefault,
            IsCancel = isCancel,
            Tag = result
        };
        button.Click += (_, _) =>
        {
            Result = result;
            Close();
        };
        ButtonPanel.Children.Add(button);
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (Result == MessageBoxResult.None)
            Result = _buttons switch
            {
                MessageBoxButton.YesNo => MessageBoxResult.No,
                MessageBoxButton.OKCancel => MessageBoxResult.Cancel,
                MessageBoxButton.YesNoCancel => MessageBoxResult.Cancel,
                _ => MessageBoxResult.OK
            };
        Close();
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }
}
