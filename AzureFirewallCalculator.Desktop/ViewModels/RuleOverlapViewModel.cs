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

    public RuleOverlapViewModel(Firewall firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;

        _ = Init();
    }

    public AvaloniaList<OverlapSummary> OverlapSummaries { get; } = [];

    public async Task Init()
    {
        // I think there's a bug in the cumulative calculations, inasmuch as it consolidates each component individually, even if other components from one rule don't match everything
        try
        {
            OverlapSummaries.Clear();
            var overlap = await Task.Run(() =>
            {
                //var coll1 = Firewall.NetworkRuleCollections[0];
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