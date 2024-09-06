using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Reactive;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Collections;
using Avalonia.Controls;
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

    public AvaloniaList<NetworkRule> NetworkRules { get; } = [];

    public IDnsResolver DnsResolver { get; }

    public RoutingState Router { get; } = new RoutingState();

    private OverlapSummary? overlapSummary;
    public OverlapSummary? OverlapSummary
    {
        get { return overlapSummary; }
        set
        {
            this.RaiseAndSetIfChanged(ref overlapSummary, value);
        }
    }

    private Task CalculatingOverlaps = Task.CompletedTask;

    private NetworkRule? selectedRule;
    public NetworkRule? SelectedRule
    {
        get { return selectedRule; }
        set
        {
            this.RaiseAndSetIfChanged(ref selectedRule, value);
            if (value != null)
            {
                CalculatingOverlaps = CalculateOverlaps(value);
            }
        }
    }

    public RuleOverlapViewModel(Firewall firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;

        NetworkRules.AddRange(firewall.NetworkRuleCollections.SelectMany(item => item.Rules));
    }

    public async Task CalculateOverlaps(NetworkRule networkRule)
    {
        var fqdnLoad = networkRule.ResolveDestinationFqdns();
        await CalculatingOverlaps; // Not sure that's a good idea; need to review the right way to handle this
        await fqdnLoad;
        var overlap = await Task.Run(() =>
        {
            return OverlapAnalyzer.CheckForOverlap(networkRule, [.. NetworkRules]);
        });
        OverlapSummary = overlap;
    }
}