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
    public string NetworkDestinationPort { get; set; } = string.Empty;
    public string ApplicationSourceIp { get; set; } = string.Empty;
    public string DestinationFqdn { get; set; } = string.Empty;
    public ApplicationProtocol[] SelectableApplicationProtocols { get; } = new [] { Core.ApplicationProtocol.Mssql, Core.ApplicationProtocol.Https, Core.ApplicationProtocol.Http };
    public ApplicationProtocol? ApplicationProtocol { get; set; } 
    public string ApplicationDestinationPort { get; set; } = string.Empty;
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
    

    public async void CheckNetworkRule()
    {
        ushort? destinationPort = ushort.TryParse(NetworkDestinationPort, out var parsedDestinationPort)
            ? parsedDestinationPort
            : null;
        if (string.IsNullOrWhiteSpace(NetworkSourceIp) 
            || string.IsNullOrWhiteSpace(NetworkDestinationIp) 
            || NetworkProtocol == NetworkProtocols.None
            || (destinationPort == null && NetworkDestinationPort != "*")
            || Firewall == null)
        {
            NetworkRuleError = "Check input";
            return;
        }

        RuleProcessingResponses.Clear();
        NetworkRuleError = null;

        IEnumerable<uint?> numericSourceIps = NetworkSourceIp == "*"
            ? new uint?[] { null }
            : IPAddress.TryParse(NetworkSourceIp, out var sourceIp)
                ? new uint?[] { sourceIp.ConvertToUint() }
                : (await DnsResolver.ResolveAddress(NetworkSourceIp)).Cast<uint?>();

        if (!numericSourceIps.Any())
        {
            NetworkRuleError = $"Unable to resolve '{NetworkSourceIp}' or treat it as an IP address";
            return;
        }
        
        IEnumerable<uint?> numericDestinationIps = NetworkDestinationIp == "*"
            ? new uint?[] { null }
            : IPAddress.TryParse(NetworkDestinationIp, out var destinationIp)
                ? new uint?[] { destinationIp.ConvertToUint() }
                : (await DnsResolver.ResolveAddress(NetworkDestinationIp)).Cast<uint?>();

        if (!numericDestinationIps.Any())
        {
            NetworkRuleError = $"Unable to resolve '{NetworkDestinationIp}' or treat it as an IP address";
            return;
        }

        var requests = numericSourceIps.SelectMany(numericSourceIp => numericDestinationIps.Select(numericDestinationIp => new NetworkRequest(numericSourceIp, numericDestinationIp, destinationPort, NetworkProtocol)));

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        Dispatcher.UIThread.Invoke(() =>
        {
            RuleProcessingResponses.AddRange(ruleProcessor.ProcessNetworkRequests(requests.ToArray()));
        });
    }

    public async Task CheckApplicationRule()
    {
        ushort? destinationPort = ushort.TryParse(ApplicationDestinationPort, out var parsedDestination)
            ? parsedDestination
            : null;
        if (string.IsNullOrWhiteSpace(ApplicationSourceIp) 
            || string.IsNullOrWhiteSpace(DestinationFqdn) 
            || (destinationPort == null && ApplicationDestinationPort != "*")
            || ApplicationProtocol == null
            || Firewall == null)
        {
            ApplicationRuleError = "Check input";
            return;
        }

        // Should be safe; haven't made async call yet
        RuleProcessingResponses.Clear();

        var portProtocol = new ApplicationProtocolPort(ApplicationProtocol.Value, destinationPort);

        // TODO: Move all this into the RuleProcessor stuff.
        IEnumerable<uint?> numericSourceIps = ApplicationSourceIp == "*"
            ? new uint?[] { null }
            : IPAddress.TryParse(ApplicationSourceIp, out var sourceIp)
                ? new uint?[] { sourceIp.ConvertToUint() }
                : (await DnsResolver.ResolveAddress(ApplicationSourceIp)).Cast<uint?>();
        
        if (!numericSourceIps.Any())
        {
            ApplicationRuleError = $"Unable to resolve '{ApplicationSourceIp}' or treat it as an IP address";
            return;
        }

        var requests = numericSourceIps.Select(item => new ApplicationRequest(item, DestinationFqdn, portProtocol));

        ApplicationRuleError = null;

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);

        var responses = (await Task.WhenAll(requests.Select(ruleProcessor.ProcessApplicationRequest))).SelectMany(item => item);

        Dispatcher.UIThread.Invoke(() =>
        {
            RuleProcessingResponses.AddRange(responses);
        });
    }
}