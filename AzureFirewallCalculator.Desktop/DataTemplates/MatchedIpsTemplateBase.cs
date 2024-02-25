using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Templates;
using Avalonia.Media;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.DataTemplates;

public abstract class MatchedIpsTemplateBase(Func<NetworkRuleMatch, RuleIpRange[]> matchedIpsSelector, Func<NetworkRule, RuleIpRange[]> ruleIpsSelector) : IDataTemplate
{
    public Func<NetworkRuleMatch, RuleIpRange[]> MatchedIpsSelector { get; } = matchedIpsSelector;
    public Func<NetworkRule, RuleIpRange[]> RuleIpsSelector { get; } = ruleIpsSelector;

    public Control? Build(object? param)
    {
        if (param is not NetworkRuleMatch match)
        {
            throw new InvalidOperationException($"Template {this.GetType().Name} expects an object of type {nameof(NetworkRuleMatch)}, but received object of type {param?.GetType().FullName}");
        }

        var matchedIps = MatchedIpsSelector(match);

        var block = new SelectableTextBlock
        {
            Inlines = [
            ..RuleIpsSelector(match.Rule).Aggregate(new List<Inline>(), (controls, item) =>
            {
                var weight = matchedIps.Contains(item)
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
        ]
        };
        block.DoubleTapped += (sender, e) =>
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
            var end = newlineIndexes.FirstOrDefault(item => item > start);

            block.SelectionStart = start;
            block.SelectionEnd = end;
        };
        return block;
    }

    public bool Match(object? data) => data is NetworkRuleMatch;
}