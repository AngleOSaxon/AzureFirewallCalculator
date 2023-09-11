using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Converters;

public class ListConcatConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        var combinedList = values.Where(item => item is IEnumerable<object>).Cast<IEnumerable<object>>().SelectMany(item =>item);
        return combinedList;
    }
}