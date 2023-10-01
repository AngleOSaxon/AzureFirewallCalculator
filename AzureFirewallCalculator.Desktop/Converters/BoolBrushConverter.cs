using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace AzureFirewallCalculator.Desktop.Converters;

// Taken from https://stackoverflow.com/a/32526689
public class BoolBrushConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        SolidColorBrush color;
        // Setting default values
        var colorIfTrue = Colors.Gray;
        var colorIfFalse = Colors.White;
        double opacity = 1;
        // Parsing converter parameter
        if (parameter != null)
        {
            // Parameter format: [ColorNameIfTrue;ColorNameIfFalse;OpacityNumber]
            var parameterstring = parameter.ToString();
            if (!string.IsNullOrEmpty(parameterstring))
            {
                var parameters = parameterstring.Split(';');
                var count = parameters.Length;
                if (count > 0 && !string.IsNullOrEmpty(parameters[0]))
                {
                    colorIfTrue = ColorFromName(parameters[0]);
                }
                if (count > 1 && !string.IsNullOrEmpty(parameters[1]))
                {
                    colorIfFalse = ColorFromName(parameters[1]);
                }
                if (count > 2 && !string.IsNullOrEmpty(parameters[2]))
                {
                    if (double.TryParse(parameters[2], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture.NumberFormat, out double dblTemp))
                        opacity = dblTemp;
                }
            }
        }
        // Creating Color Brush
        if (value != null && (bool) value)
        {
            color = new SolidColorBrush(colorIfTrue)
            {
                Opacity = opacity
            };
        }
        else
        {
            color = new SolidColorBrush(colorIfFalse)
            {
                Opacity = opacity
            };
        }
        return color;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return null;
    }

    public static Color ColorFromName(string colorName)
    {
        System.Drawing.Color systemColor = System.Drawing.Color.FromName(colorName);
        return Color.FromArgb(systemColor.A, systemColor.R, systemColor.G, systemColor.B);
    }
}