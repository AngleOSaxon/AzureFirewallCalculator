using System;
using System.Linq;
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
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);

        if (change.Property == RangeProperty && change.NewValue is RuleIpRange range)
        {
            RangeText.Text = range.ToString();
            if (range.SourcedFrom.Length == 0)
            {
                SourceLabel.IsVisible = false;
                SourceTypeLabel.IsVisible = false;
            }
            else
            {
                SourceLabel.IsVisible = true;
                SourceTypeLabel.IsVisible = true;
            }
            SourceType.Text = string.Join(", ", range.SourcedFrom.Select(item => item.SourceType.ToString()));
            Source.Text = string.Join(", ", range.SourcedFrom.Select(item => item.SourceName.ToString()));
        }
    }
}