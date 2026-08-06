using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.App.Converters;

/// <summary>
/// Converts a <see cref="ComplianceStatus"/> to the accent colour used for it.
/// </summary>
public sealed class StatusToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush PassBrush = Freeze(Color.FromRgb(0x3F, 0xB9, 0x50));
    private static readonly SolidColorBrush FailBrush = Freeze(Color.FromRgb(0xF8, 0x51, 0x49));
    private static readonly SolidColorBrush NeutralBrush = Freeze(Color.FromRgb(0x9A, 0xA1, 0xB1));

    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        ComplianceStatus.Pass => PassBrush,
        ComplianceStatus.Fail => FailBrush,
        bool failed => failed ? FailBrush : PassBrush,
        _ => NeutralBrush,
    };

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("StatusToBrushConverter is one-way.");

    private static SolidColorBrush Freeze(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }
}

/// <summary>
/// Converts a <see cref="ComplianceStatus"/> to its uppercase label.
/// </summary>
public sealed class StatusToTextConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is ComplianceStatus status ? status.ToString().ToUpperInvariant() : string.Empty;

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("StatusToTextConverter is one-way.");
}

/// <summary>
/// Collapses an element when its bound value is null, empty, or false.
/// </summary>
public sealed class EmptyToCollapsedConverter : IValueConverter
{
    /// <inheritdoc />
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var visible = value switch
        {
            null => false,
            bool flag => flag,
            string text => !string.IsNullOrWhiteSpace(text),
            int count => count > 0,
            System.Collections.ICollection collection => collection.Count > 0,
            _ => true,
        };

        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <inheritdoc />
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException("EmptyToCollapsedConverter is one-way.");
}
