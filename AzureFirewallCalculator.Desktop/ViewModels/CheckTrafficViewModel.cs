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
using System.Net;

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
    // Use Object list to stop cast exceptions when the Selected event fires.  Jesus.
    public AvaloniaList<object> RuleProcessingResponses { get; set; } = new();
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

        uint? numericSourceIp = NetworkSourceIp == "*"
            ? null
            : IPAddress.Parse(NetworkSourceIp).ConvertToUint();
        uint? numericDestinationIp = NetworkDestinationIp == "*"
            ? null
            : IPAddress.Parse(NetworkDestinationIp).ConvertToUint();

        var request = new NetworkRequest(numericSourceIp, numericDestinationIp, (ushort)NetworkDestinationPort.Value, NetworkProtocol);

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        RuleProcessingResponses.Clear();
        RuleProcessingResponses.AddRange(ruleProcessor.ProcessNetworkRequest(request));
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

        // Should be safe; haven't made async call yet
        RuleProcessingResponses.Clear();

        var portProtocol = new ApplicationProtocolPort(ApplicationProtocol.Value, (ushort)ApplicationDestinationPort.Value);
        var request = ApplicationSourceIp == "*"
            ? new ApplicationRequest(numericSourceIp: null, DestinationFqdn, portProtocol)
            : new ApplicationRequest(ApplicationSourceIp, DestinationFqdn, portProtocol);

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        var responses = await ruleProcessor.ProcessApplicationRequest(request);

        Dispatcher.UIThread.Invoke(() =>
        {
            RuleProcessingResponses.Clear();
            RuleProcessingResponses.AddRange(responses);
        });
    }
}