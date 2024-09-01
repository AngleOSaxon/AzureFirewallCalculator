using System;
using Avalonia;
using Avalonia.Controls;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class IpRangeToolTip : UserControl
{
    public static readonly StyledProperty<RuleIpRange> RangeProperty = AvaloniaProperty.Register<IpRangeDisplay, RuleIpRange>(nameof(Range), new());
    public RuleIpRange Range
    {
        get => GetValue(RangeProperty);
        set => SetValue(RangeProperty, value);
    }

    public IpRangeToolTip() : base()
    {
        InitializeComponent();
        RangeProperty.Changed.Subscribe(e => 
        {
            RangeText.Text = Range.ToString();
        });
    }
}