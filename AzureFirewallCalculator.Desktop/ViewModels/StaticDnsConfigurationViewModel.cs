using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Reactive;
using AzureFirewallCalculator.Core;
using AzureFirewallCalculator.Core.Dns;
using DynamicData;
using Microsoft.Extensions.Logging;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class StaticDnsConfigurationViewModel : ReactiveObject, IRoutableViewModel
{
    public record class Row(string Fqdn, string IpAddress);

    public StaticDnsConfigurationViewModel(IScreen hostScreen, StaticDnsResolver dnsResolver, ILogger<StaticDnsConfigurationViewModel> logger)
    {
        DnsResolver = dnsResolver;
        Logger = logger;
        HostScreen = hostScreen;
        SaveDnsCommand = ReactiveCommand.Create(() =>
        {
            dnsResolver.FqdnLookup.Clear();
            foreach (var (fqdn, ipAddress) in ConfiguredDns)
            {
                dnsResolver.FqdnLookup.Add(fqdn, new [] { IPAddress.Parse(ipAddress).ConvertToUint() });
            }
        });
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
    }

    public StaticDnsResolver DnsResolver { get; }
    public ILogger<StaticDnsConfigurationViewModel> Logger { get; }

    public ObservableCollection<Row> ConfiguredDns { get; } = new();

    public ReactiveCommand<Unit, Unit> SaveDnsCommand { get; }

    public ReactiveCommand<Unit, Unit> AddNewDnsNameCommand { get; }

    public ReactiveCommand<string, Unit> RemoveDnsNameCommand { get; }

    public string? UrlPathSegment => "static-dns";

    public IScreen HostScreen { get; }
}