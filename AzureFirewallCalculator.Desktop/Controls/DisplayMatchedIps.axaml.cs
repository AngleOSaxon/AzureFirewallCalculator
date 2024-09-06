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

    public static readonly StyledProperty<IEnumerable<RuleIpRange>> IpsProperty = AvaloniaProperty.Register<DisplayMatchedIps, IEnumerable<RuleIpRange>>(nameof(Ips), []);

    public IEnumerable<RuleIpRange> Ips
    {
        get => GetValue(IpsProperty);
        set => SetValue(IpsProperty, value);
    }

    public static readonly StyledProperty<IEnumerable<RuleIpRange>> MatchesProperty = AvaloniaProperty.Register<DisplayMatchedIps, IEnumerable<RuleIpRange>>(nameof(Matches), []);

    public IEnumerable<RuleIpRange> Matches
    {
        get => GetValue(MatchesProperty);
        set => SetValue(MatchesProperty, value);
    }

    public static readonly StyledProperty<bool> ExactMatchOnlyProperty = AvaloniaProperty.Register<DisplayMatchedIps, bool>(nameof(ExactMatchOnly), true);

    public bool ExactMatchOnly
    {
        get => GetValue(ExactMatchOnlyProperty);
        set => SetValue(ExactMatchOnlyProperty, value);
    }

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property != IpsProperty && change.Property != MatchesProperty)
        {
            return;
        }

        IpDisplay.Inlines = [
            ..Ips
                .OrderBy(item => item.Start)
                .ThenBy(item => item.End)
                .Aggregate(new List<Inline>(), (controls, item) =>
                {
                    static bool ExactMatch(IEnumerable<RuleIpRange> values, RuleIpRange item) => values.Contains(item);
                    static bool ContainedMatch(IEnumerable<RuleIpRange> values, RuleIpRange item) => values.Any(value => value.Contains(item));

                    Func<IEnumerable<RuleIpRange>, RuleIpRange, bool> shouldBold = ExactMatchOnly ? ExactMatch : ContainedMatch;

                    var weight = shouldBold(Matches, item)
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