using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using DynamicData;
using Microsoft.Extensions.Logging;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class StaticDnsConfigurationViewModel : ReactiveObject, IRoutableViewModel, IActivatableViewModel
{
    public record class Row(string Fqdn, string IpAddress);

    public StaticDnsConfigurationViewModel(IScreen hostScreen, StaticDnsResolver dnsResolver, ILogger<StaticDnsConfigurationViewModel> logger)
    {
        DnsResolver = dnsResolver;
        Logger = logger;
        HostScreen = hostScreen;
        Activator = new ViewModelActivator();
        SaveDnsCommand = ReactiveCommand.Create(SaveDns);
        AddNewDnsNameCommand = ReactiveCommand.Create(() =>
        {
            ConfiguredDns.Add(new Row(string.Empty, string.Empty));
        });
        RemoveDnsNameCommand = ReactiveCommand.Create((string fqdn) =>
        {
            var toRemove = ConfiguredDns.FirstOrDefault(item => item.Fqdn == fqdn);
            if (toRemove != null)
            {
                ConfiguredDns.Remove(toRemove);
            }
        });

        ConfiguredDns.AddRange(dnsResolver.FqdnLookup.Select(item => item.Value.Select(ip => new Row(item.Key, ip.ConvertToIpAddress().ToString()))).SelectMany(item => item));

        this.WhenActivated((CompositeDisposable disposables) =>
        {
            var subscription = HostScreen.Router.CurrentViewModel.Subscribe(Observer.Create((IRoutableViewModel? viewModel) =>
            {
                if (viewModel is not StaticDnsConfigurationViewModel)
                {
                    SaveDns();
                }
            }))
            .DisposeWith(disposables);
        });
        
    }

    public StaticDnsResolver DnsResolver { get; }
    public ILogger<StaticDnsConfigurationViewModel> Logger { get; }

    public ObservableCollection<Row> ConfiguredDns { get; } = new();

    public ReactiveCommand<Unit, Unit> SaveDnsCommand { get; }

    public ReactiveCommand<Unit, Unit> AddNewDnsNameCommand { get; }

    public ReactiveCommand<string, Unit> RemoveDnsNameCommand { get; }

    public string? UrlPathSegment => "static-dns";

    public IScreen HostScreen { get; }

    public ViewModelActivator Activator { get; }

    private void SaveDns()
    {
        DnsResolver.FqdnLookup.Clear();
        foreach (var (fqdn, ipAddress) in ConfiguredDns)
        {
            DnsResolver.FqdnLookup.Add(fqdn, [IPAddress.Parse(ipAddress).ConvertToUint()]);
        }
    }
}