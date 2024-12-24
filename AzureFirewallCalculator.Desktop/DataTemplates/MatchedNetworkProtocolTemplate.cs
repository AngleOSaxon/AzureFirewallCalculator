using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Templates;
using Avalonia.Media;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Desktop.ViewModels;

namespace AzureFirewallCalculator.Desktop.DataTemplates;

public class MatchedNetworkProtocolTemplate : IDataTemplate
{
    public Control? Build(object? param)
    {
        var (protocols, matchedProtocols) = param switch
        {
            NetworkRuleMatch match => (match.Rule.NetworkProtocols, match.MatchedProtocols),
            NetworkRuleOverlap overlap => (overlap.OverlappingRule.NetworkProtocols, overlap.OverlappingProtocols),
            OverlapSummary overlapSummary => (overlapSummary.SourceRule.NetworkProtocols, NetworkProtocols.None),
            RuleOverlapViewModel overlapViewModel => (overlapViewModel?.SelectedRule?.NetworkProtocols ?? NetworkProtocols.None, overlapViewModel?.MatchedNetworkProtocols ?? NetworkProtocols.None),
            (NetworkProtocols suppliedProtocols, NetworkProtocols suppliedMatches) => (suppliedProtocols, suppliedMatches),
            _ => throw new InvalidOperationException($"Template {nameof(MatchedNetworkProtocolTemplate)} expects an object of type {nameof(NetworkRuleMatch)} or of type {nameof(NetworkRuleOverlap)}, but received object of type {param?.GetType().FullName}")
        };

        if (protocols.HasFlag(NetworkProtocols.Any))
        {
            return new SelectableTextBlock
            {
                Text = NetworkProtocols.Any.ToString(),
                FontWeight = FontWeight.ExtraBold
            };
        }

        var block = new SelectableTextBlock();
        var ruleProtocols = Enum.GetValues<NetworkProtocols>().Where(item => item != NetworkProtocols.None && protocols.HasFlag(item));
        var inlines = ruleProtocols.SelectMany(item =>
        {
            var weight = (matchedProtocols & item) > 0
                ? FontWeight.ExtraBold
                : FontWeight.Normal;
            return new List<Run>
            {
                new(item.ToString())
                {
                    FontWeight = weight
                },
                new(", ")
            };
        })
        .SkipLast(1);

        block.Inlines = [..inlines];
        return block;
    }

    public bool Match(object? data) => data is NetworkRuleMatch || data is NetworkRuleOverlap || data is OverlapSummary || data is RuleOverlapViewModel || data is (NetworkProtocols, NetworkProtocols);
}