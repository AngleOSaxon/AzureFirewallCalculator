using System;
using System.Collections.Immutable;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Avalonia.Collections;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class RuleOverlapViewModel : ReactiveObject, IRoutableViewModel
{
    public const string RuleOverlapUrlPathSegment = "rule-overlap";
    public string? UrlPathSegment => RuleOverlapUrlPathSegment;

    public IScreen HostScreen { get; }

    public Firewall Firewall { get; set; }

    public IDnsResolver DnsResolver { get; }

    public RoutingState Router { get; } = new RoutingState();

    public AvaloniaList<object> OverlapSummaries { get; } = [];

    public RuleOverlapViewModel(Firewall firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;

        _ = Init();
    }

    public async Task Init()
    {
        try
        {
            OverlapSummaries.Clear();
            var overlap = await Task.Run(() =>
            {
                var networkRules = Firewall.NetworkRuleCollections.SelectMany(item => item.Rules).ToArray();
                var results = networkRules.Select(item => OverlapAnalyzer.CheckForOverlap(item, networkRules)).Where(item => item.CumulativeOverlap != OverlapType.None).ToList();
                return results;
            });
            OverlapSummaries.AddRange(overlap);
        }
        catch (Exception e)
        {
            // TODO: logging
        }
    }
}