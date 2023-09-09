using System;
using System.Threading.Tasks;
using Avalonia.Collections;
using AzureFirewallCalculator.Core.Dns;
using ReactiveUI;
using System.Linq;
using AzureFirewallCalculator.Core;
using System.Reactive.Linq;
using System.Collections.Generic;
using System.Reactive;
using System.Collections.ObjectModel;
using DynamicData;
using Avalonia.Threading;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class CheckTrafficViewModel : ReactiveObject, IRoutableViewModel
{
    public CheckTrafficViewModel(Firewall? firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;
        CheckNetworkRuleCommand = ReactiveCommand.Create(() => CheckNetworkRule());
        CheckApplicationRuleCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => CheckApplicationRule()));
    }

    public Firewall? Firewall { get; set; }
    public IDnsResolver DnsResolver { get; }
    public string NetworkSourceIp { get; set; } = string.Empty;
    public string NetworkDestinationIp { get; set; } = string.Empty;
    public NetworkProtocols[] SelectableNetworkProtocols { get; } = new [] { NetworkProtocols.TCP, NetworkProtocols.UDP, NetworkProtocols.ICMP };
    public NetworkProtocols NetworkProtocol { get; set; } 
    public int? NetworkDestinationPort { get; set; }
    public string ApplicationSourceIp { get; set; } = string.Empty;
    public string DestinationFqdn { get; set; } = string.Empty;
    public ApplicationProtocol[] SelectableApplicationProtocols { get; } = new [] { Core.ApplicationProtocol.Mssql, Core.ApplicationProtocol.Https, Core.ApplicationProtocol.Http };
    public ApplicationProtocol? ApplicationProtocol { get; set; } 
    public int? ApplicationDestinationPort { get; set; }
    public ObservableCollection<NetworkProcessingResponse> NetworkProcessingResponses { get; set; } = new();
    public AvaloniaList<ApplicationProcessingResponse> ApplicationProcessingResponses { get; set; } = new();
    public ReactiveCommand<Unit, Unit> CheckNetworkRuleCommand { get; }
    public ReactiveCommand<Unit, Task> CheckApplicationRuleCommand { get; }
    public string? UrlPathSegment => "check-traffic";
    public IScreen HostScreen { get; }
    private string? networkRuleError;
    public string? NetworkRuleError
    {
        get { return networkRuleError; }
        set { this.RaiseAndSetIfChanged(ref networkRuleError, value); }
    }
    private string? applicationRuleError;
    public string? ApplicationRuleError
    {
        get { return applicationRuleError; }
        set { this.RaiseAndSetIfChanged(ref applicationRuleError, value); }
    }
    

    public void CheckNetworkRule()
    {
        if (string.IsNullOrWhiteSpace(NetworkSourceIp) 
            || string.IsNullOrWhiteSpace(NetworkDestinationIp) 
            || NetworkDestinationPort == null 
            || NetworkProtocol == NetworkProtocols.None
            || Firewall == null)
        {
            NetworkRuleError = "Check input";
            return;
        }

        NetworkRuleError = null;

        NetworkProcessingResponses.Clear();
        ApplicationProcessingResponses.Clear();

        var request = new NetworkRequest(NetworkSourceIp, NetworkDestinationIp, (ushort)NetworkDestinationPort.Value, NetworkProtocol);

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        NetworkProcessingResponses.AddRange(ruleProcessor.ProcessNetworkRequest(request).OrderBy(item => item.Priority));
    }

    public async Task CheckApplicationRule()
    {
        if (string.IsNullOrWhiteSpace(ApplicationSourceIp) 
            || string.IsNullOrWhiteSpace(DestinationFqdn) 
            || ApplicationDestinationPort == null 
            || ApplicationProtocol == null
            || Firewall == null)
        {
            ApplicationRuleError = "Check input";
            return;
        }

        ApplicationRuleError = null;

        Dispatcher.UIThread.Invoke(() =>
        {
            NetworkProcessingResponses.Clear();
            ApplicationProcessingResponses.Clear();
        });

        var request = new ApplicationRequest(ApplicationSourceIp, DestinationFqdn, new ApplicationProtocolPort(ApplicationProtocol.Value, (ushort)ApplicationDestinationPort.Value));

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        var responses = await ruleProcessor.ProcessApplicationRequest(request);

        var (network, application) = responses.Aggregate((networkRules: new List<NetworkProcessingResponse>(), applicationRules: new List<ApplicationProcessingResponse>()), (aggregate, item) =>
        {
            var (networkRules, applicationRules) = aggregate;

            if (item is NetworkProcessingResponse networkResponse)
            {
                networkRules.Add(networkResponse);
            }
            else if (item is ApplicationProcessingResponse applicationResponse)
            {
                applicationRules.Add(applicationResponse);
            }
            else
            {
                throw new Exception($"Received item of unexpected type '{item.GetType().FullName}'");
            }

            return aggregate;
        });

        Dispatcher.UIThread.Invoke(() =>
        {
            NetworkProcessingResponses.AddRange(network.OrderBy(item => item.Priority));
            ApplicationProcessingResponses.AddRange(application.OrderBy(item => item.Priority));
        });
    }
}