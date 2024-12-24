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

public class IpGroupOverlapViewModel : ReactiveObject, IRoutableViewModel
{
    public const string IpGroupOverlapUrlPathSegment = "ip-group-overlap";
    public string? UrlPathSegment => IpGroupOverlapUrlPathSegment;

    public IScreen HostScreen { get; }

    public Firewall Firewall { get; set; }

    public AvaloniaList<NetworkRule> NetworkRules { get; } = [];

    public IDnsResolver DnsResolver { get; }

    public RoutingState Router { get; } = new RoutingState();

    public IpGroupOverlapViewModel(Firewall firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;
    }

    private Task CalculatingOverlaps = Task.CompletedTask;

    private IpGroup? selectedIpGroup;
    public IpGroup? SelectedIpGroup
    {
        get { return selectedIpGroup; }
        set
        {
            this.RaiseAndSetIfChanged(ref selectedIpGroup, value);
            if (value != null)
            {
                CalculatingOverlaps = CalculateOverlaps(value);
            }
        }
    }
    private IpGroupOverlap[] overlaps = [];
    public IpGroupOverlap[] Overlaps
    {
        get { return overlaps; }
        set { this.RaiseAndSetIfChanged(ref overlaps, value); }
    }

    public Task CalculateOverlaps(IpGroup ipGroup)
    {
        var overlaps = OverlapAnalyzer.CheckForOverlap(ipGroup, Firewall.IpGroups);
        Overlaps = overlaps;

        return Task.CompletedTask;
    }
}