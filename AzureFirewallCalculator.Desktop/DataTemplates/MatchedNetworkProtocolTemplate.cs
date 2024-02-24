using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Templates;
using Avalonia.Media;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Desktop.DataTemplates;

public class MatchedNetworkProtocolTemplate : IDataTemplate
{
    public Control? Build(object? param)
    {
        if (param is not NetworkRuleMatch match)
        {
            throw new InvalidOperationException($"Template {nameof(MatchedNetworkProtocolTemplate)} expects an object of type {nameof(NetworkRuleMatch)}, but received object of type {param?.GetType().FullName}");
        }

        if (match.Rule.NetworkProtocols.HasFlag(NetworkProtocols.Any))
        {
            return new SelectableTextBlock
            {
                Text = NetworkProtocols.Any.ToString(),
                FontWeight = FontWeight.ExtraBold
            };
        }

        var block = new SelectableTextBlock();
        var ruleProtocols = Enum.GetValues<NetworkProtocols>().Where(item => item != NetworkProtocols.None && match.Rule.NetworkProtocols.HasFlag(item));
        var inlines = ruleProtocols.SelectMany(item =>
        {
            var weight = (match.MatchedProtocols & item) > 0
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

    public bool Match(object? data) => data is NetworkRuleMatch;
}