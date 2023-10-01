using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Desktop.Converters;

public class LogLevelConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not LogLevel logLevel)
        {
            return null;
        }

        if (targetType == typeof(string))
        {
            return logLevel switch
            {
                LogLevel.Trace => "TRC",
                LogLevel.Debug => "DBG",
                LogLevel.Warning => "WRN",
                LogLevel.Information => "INF",
                LogLevel.Error => "ERR",
                LogLevel.Critical => "CRIT",
                _ => "UNK"
            };
        }

        if (targetType == typeof(IBrush))
        {
            return logLevel switch
            {
                LogLevel.Error => Brushes.Red,
                LogLevel.Critical => Brushes.Red,
                LogLevel.Warning => Brushes.Orange,
                _ => Brushes.Black
            };
        }

        throw new NotImplementedException();
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return null;
    }
}
