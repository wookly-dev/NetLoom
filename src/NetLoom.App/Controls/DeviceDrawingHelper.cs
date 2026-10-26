using System.Windows;
using System.Windows.Media;
using NetLoom.App.Models;

namespace NetLoom.App.Controls;

public static class DeviceDrawingHelper
{
    private const double DesignSize = 24.0;

    public static void Draw(DrawingContext dc, DeviceType type, Rect bounds, Brush brush)
    {
        if (bounds.Width <= 0 || bounds.Height <= 0) return;

        var pen = new Pen(brush, Math.Max(1.35, Math.Min(bounds.Width, bounds.Height) / 13.0))
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        };

        Point P(double x, double y) => new(
            bounds.Left + bounds.Width * x / DesignSize,
            bounds.Top + bounds.Height * y / DesignSize);

        Rect R(double x, double y, double w, double h) => new(
            bounds.Left + bounds.Width * x / DesignSize,
            bounds.Top + bounds.Height * y / DesignSize,
            bounds.Width * w / DesignSize,
            bounds.Height * h / DesignSize);

        switch (type)
        {
            case DeviceType.Pc:
                dc.DrawRoundedRectangle(null, pen, R(3, 4, 18, 11), 1.5, 1.5);
                dc.DrawLine(pen, P(12, 15), P(12, 19));
                dc.DrawLine(pen, P(8, 19), P(16, 19));
                break;

            case DeviceType.Mobile:
                dc.DrawRoundedRectangle(null, pen, R(6.5, 2.5, 11, 19), 2.3, 2.3);
                dc.DrawEllipse(brush, null, P(12, 18.8), bounds.Width * 1.0 / DesignSize, bounds.Height * 1.0 / DesignSize);
                break;

            case DeviceType.Router:
                dc.DrawRoundedRectangle(null, pen, R(3, 11, 18, 8), 2, 2);
                dc.DrawLine(pen, P(7, 11), P(5.5, 6));
                dc.DrawLine(pen, P(17, 11), P(18.5, 6));
                DrawWifi(dc, pen, bounds, 12, 8.3, 5.0);
                dc.DrawEllipse(brush, null, P(7.2, 15.1), bounds.Width * 0.8 / DesignSize, bounds.Height * 0.8 / DesignSize);
                dc.DrawEllipse(brush, null, P(10.4, 15.1), bounds.Width * 0.8 / DesignSize, bounds.Height * 0.8 / DesignSize);
                break;

            case DeviceType.Switch:
                dc.DrawRoundedRectangle(null, pen, R(2.5, 7, 19, 10), 2, 2);
                for (int i = 0; i < 5; i++)
                    dc.DrawRectangle(null, pen, R(5 + i * 3.0, 11.1, 1.7, 1.7));
                dc.DrawLine(pen, P(6, 19), P(18, 19));
                break;

            case DeviceType.Hub:
                dc.DrawRoundedRectangle(null, pen, R(3, 8, 18, 8.5), 2, 2);
                for (int i = 0; i < 4; i++)
                    dc.DrawEllipse(null, pen, P(7 + i * 3.3, 12.2), bounds.Width * 0.75 / DesignSize, bounds.Height * 0.75 / DesignSize);
                dc.DrawLine(pen, P(6, 19), P(18, 19));
                break;

            case DeviceType.AccessPoint:
                dc.DrawRoundedRectangle(null, pen, R(7, 15.5, 10, 4.5), 2, 2);
                DrawWifi(dc, pen, bounds, 12, 13.2, 7.0);
                dc.DrawEllipse(brush, null, P(12, 12.8), bounds.Width * 0.8 / DesignSize, bounds.Height * 0.8 / DesignSize);
                break;

            case DeviceType.WifiExtender:
                dc.DrawRoundedRectangle(null, pen, R(7.5, 13.5, 9, 7), 2.2, 2.2);
                DrawWifi(dc, pen, bounds, 12, 11.5, 6.0);
                dc.DrawLine(pen, P(9.2, 17), P(14.8, 17));
                dc.DrawEllipse(brush, null, P(12, 17), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                break;

            case DeviceType.Firewall:
                dc.DrawRoundedRectangle(null, pen, R(3, 5, 18, 14), 2, 2);
                dc.DrawLine(pen, P(7, 5), P(7, 19));
                dc.DrawLine(pen, P(12, 5), P(12, 19));
                dc.DrawLine(pen, P(17, 5), P(17, 19));
                dc.DrawLine(pen, P(3, 9.7), P(21, 9.7));
                dc.DrawLine(pen, P(3, 14.3), P(21, 14.3));
                break;

            case DeviceType.Nas:
                dc.DrawRoundedRectangle(null, pen, R(4, 4, 16, 7), 1.6, 1.6);
                dc.DrawRoundedRectangle(null, pen, R(4, 13, 16, 7), 1.6, 1.6);
                dc.DrawEllipse(brush, null, P(7.2, 7.5), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                dc.DrawEllipse(brush, null, P(7.2, 16.5), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                break;

            case DeviceType.Server:
                for (int i = 0; i < 3; i++)
                {
                    double y = 3 + i * 6.2;
                    dc.DrawRoundedRectangle(null, pen, R(4, y, 16, 4.6), 1.2, 1.2);
                    dc.DrawEllipse(brush, null, P(7, y + 2.3), bounds.Width * 0.55 / DesignSize, bounds.Height * 0.55 / DesignSize);
                }
                break;

            case DeviceType.Hypervisor:
                dc.DrawRoundedRectangle(null, pen, R(3.5, 4, 17, 16), 2, 2);
                dc.DrawRectangle(null, pen, R(6, 7, 5, 4));
                dc.DrawRectangle(null, pen, R(13, 7, 5, 4));
                dc.DrawRectangle(null, pen, R(6, 13, 5, 4));
                dc.DrawRectangle(null, pen, R(13, 13, 5, 4));
                break;

            case DeviceType.Printer:
                dc.DrawRectangle(null, pen, R(7, 2.5, 10, 6));
                dc.DrawRoundedRectangle(null, pen, R(4, 8.5, 16, 9), 1.8, 1.8);
                dc.DrawRectangle(null, pen, R(7, 14, 10, 7));
                dc.DrawEllipse(brush, null, P(16.5, 11.5), bounds.Width * 0.55 / DesignSize, bounds.Height * 0.55 / DesignSize);
                break;

            case DeviceType.VoipPhone:
                dc.DrawRoundedRectangle(null, pen, R(5, 6, 14, 13), 2, 2);
                dc.DrawLine(pen, P(8, 9), P(16, 9));
                dc.DrawLine(pen, P(8, 12), P(16, 12));
                dc.DrawEllipse(brush, null, P(9, 16), bounds.Width * 0.65 / DesignSize, bounds.Height * 0.65 / DesignSize);
                dc.DrawEllipse(brush, null, P(12, 16), bounds.Width * 0.65 / DesignSize, bounds.Height * 0.65 / DesignSize);
                dc.DrawEllipse(brush, null, P(15, 16), bounds.Width * 0.65 / DesignSize, bounds.Height * 0.65 / DesignSize);
                dc.DrawLine(pen, P(7, 4), P(17, 4));
                break;

            case DeviceType.Camera:
                dc.DrawRoundedRectangle(null, pen, R(3, 7, 14, 9), 2, 2);
                dc.DrawEllipse(null, pen, P(10, 11.5), bounds.Width * 2.7 / DesignSize, bounds.Height * 2.7 / DesignSize);
                dc.DrawLine(pen, P(17, 9), P(21, 6));
                dc.DrawLine(pen, P(17, 14), P(21, 17));
                dc.DrawLine(pen, P(10, 16), P(10, 20));
                break;

            case DeviceType.Ups:
                dc.DrawRoundedRectangle(null, pen, R(6, 3, 12, 18), 2, 2);
                dc.DrawEllipse(null, pen, P(12, 8), bounds.Width * 2.2 / DesignSize, bounds.Height * 2.2 / DesignSize);
                dc.DrawLine(pen, P(10.5, 13.5), P(13.5, 13.5));
                dc.DrawLine(pen, P(12, 12), P(12, 15));
                dc.DrawEllipse(brush, null, P(12, 18), bounds.Width * 0.6 / DesignSize, bounds.Height * 0.6 / DesignSize);
                break;

            case DeviceType.IoT:
                dc.DrawEllipse(null, pen, P(12, 12), bounds.Width * 5.2 / DesignSize, bounds.Height * 5.2 / DesignSize);
                dc.DrawLine(pen, P(12, 6.8), P(12, 3));
                dc.DrawLine(pen, P(17.2, 12), P(21, 12));
                dc.DrawLine(pen, P(12, 17.2), P(12, 21));
                dc.DrawLine(pen, P(6.8, 12), P(3, 12));
                dc.DrawEllipse(brush, null, P(12, 12), bounds.Width * 1.1 / DesignSize, bounds.Height * 1.1 / DesignSize);
                break;

            case DeviceType.NetworkDevice:
                dc.DrawRoundedRectangle(null, pen, R(4, 5, 16, 14), 2, 2);
                dc.DrawLine(pen, P(7, 9), P(17, 9));
                dc.DrawLine(pen, P(7, 13), P(17, 13));
                dc.DrawEllipse(brush, null, P(8, 16.5), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                dc.DrawEllipse(brush, null, P(12, 16.5), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                dc.DrawEllipse(brush, null, P(16, 16.5), bounds.Width * 0.7 / DesignSize, bounds.Height * 0.7 / DesignSize);
                break;

            case DeviceType.Internet:
                // Simple cloud glyph for an external/public network anchor.
                dc.DrawEllipse(null, pen, P(9.0, 12.5), bounds.Width * 4.0 / DesignSize, bounds.Height * 3.0 / DesignSize);
                dc.DrawEllipse(null, pen, P(14.0, 10.0), bounds.Width * 4.2 / DesignSize, bounds.Height * 3.4 / DesignSize);
                dc.DrawEllipse(null, pen, P(17.2, 13.2), bounds.Width * 3.3 / DesignSize, bounds.Height * 2.7 / DesignSize);
                dc.DrawLine(pen, P(6.2, 15.2), P(19.7, 15.2));
                break;

            default:
                dc.DrawEllipse(null, pen, P(12, 12), bounds.Width * 5.4 / DesignSize, bounds.Height * 5.4 / DesignSize);
                dc.DrawLine(pen, P(12, 6.6), P(12, 3));
                dc.DrawLine(pen, P(17.4, 12), P(21, 12));
                dc.DrawLine(pen, P(12, 17.4), P(12, 21));
                dc.DrawLine(pen, P(6.6, 12), P(3, 12));
                break;
        }
    }

    private static void DrawWifi(DrawingContext dc, Pen pen, Rect bounds, double cx, double cy, double radius)
    {
        DrawArc(dc, pen, bounds, cx, cy, radius, 215, 325);
        DrawArc(dc, pen, bounds, cx, cy + 0.1, radius * 0.62, 215, 325);
    }

    private static void DrawArc(DrawingContext dc, Pen pen, Rect bounds, double cx, double cy, double radius, double startDeg, double endDeg)
    {
        Point P(double x, double y) => new(
            bounds.Left + bounds.Width * x / DesignSize,
            bounds.Top + bounds.Height * y / DesignSize);

        double startRad = startDeg * Math.PI / 180.0;
        double endRad = endDeg * Math.PI / 180.0;
        var start = P(cx + Math.Cos(startRad) * radius, cy + Math.Sin(startRad) * radius);
        var end = P(cx + Math.Cos(endRad) * radius, cy + Math.Sin(endRad) * radius);
        var size = new Size(bounds.Width * radius / DesignSize, bounds.Height * radius / DesignSize);

        var geometry = new StreamGeometry();
        using (var ctx = geometry.Open())
        {
            ctx.BeginFigure(start, false, false);
            ctx.ArcTo(end, size, 0, false, SweepDirection.Clockwise, true, false);
        }
        geometry.Freeze();
        dc.DrawGeometry(null, pen, geometry);
    }
}
