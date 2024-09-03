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

    // public AvaloniaList<object> OverlapSummaries { get; } = [];

    //public OverlapSummary? OverlapSummary { get; set; }
    private OverlapSummary? overlapSummary;
    public OverlapSummary? OverlapSummary
    {
        get { return overlapSummary; }
        set
        {
            this.RaiseAndSetIfChanged(ref overlapSummary, value);
        }
    }
    

    public AutoCompleteFilterPredicate<object?> AutoCompleteFilterPredicate { get; init; }

    public AutoCompleteSelector<object?> AutoCompleteSelector { get; init; }

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
        AutoCompleteFilterPredicate = new AutoCompleteFilterPredicate<object?>(Filter);
        AutoCompleteSelector = new AutoCompleteSelector<object?>((searchText, item) => (item as NetworkRule)?.Name ?? "Unknown type");

        NetworkRules.AddRange(firewall.NetworkRuleCollections.SelectMany(item => item.Rules));
    }

    public bool Filter(string? searchText, object? rule)
    {
        if (string.IsNullOrWhiteSpace(searchText))
        {
            return false;
        }

        return (rule as NetworkRule)?.Name.Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ?? false;
    }

    public async Task CalculateOverlaps(NetworkRule networkRule)
    {
        await CalculatingOverlaps; // Not sure that's a good idea; need to review the right way to handle this
        var overlap = await Task.Run(() =>
        {
            return OverlapAnalyzer.CheckForOverlap(networkRule, [.. NetworkRules]);
        });
        OverlapSummary = overlap;
    }
}