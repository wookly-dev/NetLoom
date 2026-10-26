using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetLoom.App.Models;

namespace NetLoom.App.Controls;

public sealed class DeviceGlyphControl : Control
{
    public static readonly DependencyProperty DeviceTypeProperty = DependencyProperty.Register(
        nameof(DeviceType),
        typeof(DeviceType),
        typeof(DeviceGlyphControl),
        new FrameworkPropertyMetadata(DeviceType.Unknown, FrameworkPropertyMetadataOptions.AffectsRender));

    public DeviceType DeviceType
    {
        get => (DeviceType)GetValue(DeviceTypeProperty);
        set => SetValue(DeviceTypeProperty, value);
    }

    public DeviceGlyphControl()
    {
        Focusable = false;
        IsHitTestVisible = false;
        Foreground = Brushes.White;
    }

    protected override void OnRender(DrawingContext drawingContext)
    {
        base.OnRender(drawingContext);
        var inset = Math.Max(0.5, Math.Min(ActualWidth, ActualHeight) * 0.05);
        DeviceDrawingHelper.Draw(
            drawingContext,
            DeviceType,
            new Rect(inset, inset, Math.Max(0, ActualWidth - inset * 2), Math.Max(0, ActualHeight - inset * 2)),
            Foreground);
    }
}
