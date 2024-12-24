using System;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading.Tasks;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class LoadedFirewallViewModel : ReactiveObject, IRoutableViewModel, IScreen
{
    public string? UrlPathSegment => "firewall";

    public IScreen HostScreen { get; }

    public Firewall Firewall { get; set; }

    public IDnsResolver DnsResolver { get; }

    public RoutingState Router { get; } = new RoutingState();

    public LoadedFirewallViewModel(Firewall firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;

        Router.Navigate.Execute(new CheckTrafficViewModel(Firewall, DnsResolver, this)).Wait();
    }

    public async Task NavigateTo(string tabName)
    {
        if (tabName == Router.NavigationStack.Last().UrlPathSegment)
        {
            return;
        }

        await Router.NavigateBack.Execute();
        IRoutableViewModel newDestination = tabName switch
        {
            CheckTrafficViewModel.CheckTrafficUrlPathSegment => new CheckTrafficViewModel(Firewall, DnsResolver, this),
            RuleOverlapViewModel.RuleOverlapUrlPathSegment => new RuleOverlapViewModel(Firewall, DnsResolver, this),
            IpGroupOverlapViewModel.IpGroupOverlapUrlPathSegment => new IpGroupOverlapViewModel(Firewall, DnsResolver, this),
            _ => throw new InvalidOperationException($"Unknown view '{tabName}'"),
        };
        await Router.Navigate.Execute(newDestination);
    }
}