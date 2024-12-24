using System.Linq;
using System.Reactive.Linq;
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

    private RuleIpRange[] matchedSources = [];
    public RuleIpRange[] MatchedSources
    {
        get { return matchedSources; }
        set { this.RaiseAndSetIfChanged(ref matchedSources, value); }
    }
    
    private RuleIpRange[] matchedDestinations = [];
    public RuleIpRange[] MatchedDestinations
    {
        get { return matchedDestinations; }
        set { this.RaiseAndSetIfChanged(ref matchedDestinations, value); }
    }

    private RulePortRange[] matchedPorts = [];
    public RulePortRange[] MatchedPorts
    {
        get { return matchedPorts; }
        set { this.RaiseAndSetIfChanged(ref matchedPorts, value); }
    }

    private NetworkProtocols matchedNetworkProtocols = NetworkProtocols.None;
    public NetworkProtocols MatchedNetworkProtocols
    {
        get { return matchedNetworkProtocols; }
        set { this.RaiseAndSetIfChanged(ref matchedNetworkProtocols, value); }
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
        MatchedSources = [ ..overlap.Overlaps.SelectMany(item => item.OverlappingSourceRanges).DistinctBy(item => (item.Start, item.End)) ];
        MatchedDestinations = [ ..overlap.Overlaps.SelectMany(item => item.OverlappingDestinationRanges).DistinctBy(item => (item.Start, item.End)) ];
        MatchedPorts = [ ..overlap.Overlaps.SelectMany(item => item.OverlappingPorts).Distinct() ];
        MatchedNetworkProtocols = overlap.Overlaps.Aggregate(seed: NetworkProtocols.None, (matchedProtocols, overlap) => overlap.OverlappingProtocols | matchedProtocols);
        OverlapSummary = overlap;
    }
}