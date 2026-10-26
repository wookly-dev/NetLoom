using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using NetLoom.App.Services;

namespace NetLoom.App.Windows;

public partial class PortPickerWindow : Window
{
    public ObservableCollection<PortChoiceItem> PortItems { get; } = new();
    public IReadOnlyList<int> SelectedPorts { get; private set; } = Array.Empty<int>();

    public PortPickerWindow(IEnumerable<int> selectedPorts)
    {
        InitializeComponent();
        DataContext = this;

        var selected = new HashSet<int>(selectedPorts);
        foreach (var p in CommonPortCatalog.All)
        {
            var item = new PortChoiceItem
            {
                Port = p.Port,
                Service = p.Service,
                Category = p.Category,
                Description = p.Description,
                IsSelected = selected.Contains(p.Port)
            };
            item.PropertyChanged += Item_PropertyChanged;
            PortItems.Add(item);
        }

        CategoryCombo.Items.Add("전체");
        foreach (var category in CommonPortCatalog.All.Select(p => p.Category).Distinct().OrderBy(x => x))
            CategoryCombo.Items.Add(category);
        CategoryCombo.SelectedIndex = 0;

        CollectionViewSource.GetDefaultView(PortItems).Filter = FilterPort;
        UpdateSelectedCount();
    }

    private bool FilterPort(object obj)
    {
        if (obj is not PortChoiceItem item) return false;

        var keyword = SearchTextBox.Text?.Trim() ?? "";
        var category = CategoryCombo.SelectedItem?.ToString() ?? "전체";

        bool categoryOk = category == "전체" || item.Category == category;
        bool keywordOk = string.IsNullOrWhiteSpace(keyword) ||
                         item.Port.ToString().Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                         item.Service.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                         item.Description.Contains(keyword, StringComparison.OrdinalIgnoreCase);
        return categoryOk && keywordOk;
    }

    private void Filter_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        CollectionViewSource.GetDefaultView(PortItems).Refresh();
    }

    private void Preset_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement element || element.Tag is not string preset ||
            !CommonPortCatalog.Presets.TryGetValue(preset, out var ports))
            return;

        var target = ports.ToHashSet();
        foreach (var item in PortItems)
            item.IsSelected = target.Contains(item.Port);
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in PortItems)
            item.IsSelected = false;
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        var selected = PortItems.Where(x => x.IsSelected).Select(x => x.Port).OrderBy(x => x).ToArray();
        if (selected.Length > 64)
        {
            ThemedMessageBox.Show("TCP 포트는 한 번에 최대 64개까지 선택할 수 있습니다.", "NetLoom", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SelectedPorts = selected;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private void Close_Click(object sender, RoutedEventArgs e) => DialogResult = false;

    private void Item_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PortChoiceItem.IsSelected))
            UpdateSelectedCount();
    }

    private void UpdateSelectedCount()
    {
        if (SelectedCountText is null) return;
        SelectedCountText.Text = $"선택 {PortItems.Count(x => x.IsSelected)}개";
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    public sealed class PortChoiceItem : INotifyPropertyChanged
    {
        private bool _isSelected;
        public int Port { get; init; }
        public string Service { get; init; } = "";
        public string Category { get; init; } = "";
        public string Description { get; init; } = "";

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
