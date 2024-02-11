using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace AzureFirewallCalculator.Desktop.Converters;

public class AdditionConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is double startingValue && (parameter is double addend || double.TryParse(parameter?.ToString(), out addend)))
        {
            return startingValue + addend;
        }
        return value;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}