using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Media;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.Controls;

public partial class DisplayMatchedIps : UserControl
{
    public DisplayMatchedIps()
    {
        InitializeComponent();
        IpDisplay.DoubleTapped += (sender, e) =>
        {
            if (e.Source is not SelectableTextBlock block)
            {
                return;
            }

            var texthit = block.TextLayout.HitTestPoint(e.GetPosition(block));
            var newlineIndexes = new List<int>();
            int index = 0;
            while (index != -1)
            {
                index = block.Inlines?.Text?.IndexOf(Environment.NewLine, index + 1) ?? -1;
                if (index == -1)
                {
                    break;
                }
                newlineIndexes.Add(index);
            }
            newlineIndexes.Add(block.Inlines?.Text?.Length ?? 0);

            var start = newlineIndexes.LastOrDefault(item => texthit.CharacterHit.FirstCharacterIndex >= item);
            if (start != default) // If we're not on the first line, advance far enough to not include the newlines from the previous line
            {
                start += Environment.NewLine.Length;
            }
            var end = newlineIndexes.FirstOrDefault(item => item > start);

            block.SelectionStart = start;
            block.SelectionEnd = end;
        };
    }

    public static readonly StyledProperty<RuleIpRange[]> IpsProperty = AvaloniaProperty.Register<DisplayMatchedIps, RuleIpRange[]>(nameof(Ips), []);

    public RuleIpRange[] Ips
    {
        get => GetValue(IpsProperty);
        set => SetValue(IpsProperty, value);
    }

    public static readonly StyledProperty<RuleIpRange[]> MatchesProperty = AvaloniaProperty.Register<DisplayMatchedIps, RuleIpRange[]>(nameof(Matches), []);

    public RuleIpRange[] Matches
    {
        get => GetValue(MatchesProperty);
        set => SetValue(MatchesProperty, value);
    }

    //private SelectableTextBlock IpDisplay => this.FindControl<SelectableTextBlock>("IpDisplay") ?? throw new InvalidOperationException("Unable to find expected element named 'IpDisplay'");

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property != IpsProperty && change.Property != MatchesProperty)
        {
            return;
        }

        IpDisplay.Inlines = [
            ..Ips.Aggregate(new List<Inline>(), (controls, item) =>
            {
                var weight = Matches.Contains(item)
                    ? FontWeight.ExtraBold
                    : FontWeight.Normal;

                controls.Add(new Run(item.ToString())
                {
                    FontWeight = weight
                });
                controls.Add(new LineBreak());
                return controls;
            })
            .SkipLast(1)
        ];
    }
}