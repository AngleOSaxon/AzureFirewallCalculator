using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Converters;

public class MatchFontWeightConverter : IMultiValueConverter
{
    public object? Convert(IList<object?> values, Type targetType, object? parameter, CultureInfo culture)
    {
        if (values == null || values.Count != 2)
        {
            throw new ArgumentException($"Invalid input values for '{nameof(MatchFontWeightConverter)}'. ({(values == null ? "null" : values.Count)}) values.");
        }
        if (values[0]?.GetType() == typeof(UnsetValueType) || values[1]?.GetType() == typeof(UnsetValueType))
        {
            return FontWeight.Regular;
        }
        if (targetType != typeof(FontWeight))
        {
            throw new ArgumentException($"Invalid target type for '{nameof(MatchFontWeightConverter)}'");
        }
        if (values[0] is RuleIpRange ipRange && values[1] is RuleIpRange[] matchedIpRanges)
        {
            return matchedIpRanges.Contains(ipRange) ? FontWeight.ExtraBold : FontWeight.Regular;
        }
        if (values[0] is string domainName && values[1] is string[] matchedDomainNames)
        {
            return matchedDomainNames.Contains(domainName) ? FontWeight.ExtraBold : FontWeight.Regular;
        }

        throw new ArgumentException($"Invalid input values. Expected '{nameof(RuleIpRange)}' and '{typeof(RuleIpRange[]).GetType().FullName}' or '{nameof(String)}' and '{typeof(string[]).GetType().FullName}', received '{values[0]?.GetType().FullName}' and '{values[1]?.GetType().FullName}'");
    }
}