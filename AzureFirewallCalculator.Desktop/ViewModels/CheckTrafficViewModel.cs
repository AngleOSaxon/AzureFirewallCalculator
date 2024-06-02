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
using System.ComponentModel;
using System.Collections;
using OneOf;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public record struct ResolvedDns(string Fqdn, IPAddress[] Addresses);

public class CheckTrafficViewModel : ReactiveObject, IRoutableViewModel, INotifyDataErrorInfo
{
    public CheckTrafficViewModel(Firewall? firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;
        CheckFirewallRulesCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => CheckFirewallRules()));
    }

    private readonly Dictionary<string, IEnumerable<string>> errorMessages = new(StringComparer.CurrentCultureIgnoreCase);
    public Firewall? Firewall { get; set; }
    public IDnsResolver DnsResolver { get; }
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string DestinationPort { get; set; } = string.Empty;
    public string[] SelectableProtocols { get; } = new object[] 
    { 
        NetworkProtocols.ICMP,
        NetworkProtocols.TCP,
        NetworkProtocols.UDP,
        ApplicationProtocol.Mssql,
        ApplicationProtocol.Https,
        ApplicationProtocol.Http
    }.Select(item => item.ToString()!).ToArray();
    public string? SelectedProtocol { get; set; } = null;
    // Use Object list to stop cast exceptions when the Selected event fires.  Jesus.
    public AvaloniaList<object> RuleProcessingResponses { get; set; } = [];
    public ReactiveCommand<Unit, Task> CheckFirewallRulesCommand { get; }
    public const string CheckTrafficUrlPathSegment = "check-traffic";
    public string? UrlPathSegment => CheckTrafficUrlPathSegment;
    public IScreen HostScreen { get; }
    public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;
    public AvaloniaList<ResolvedDns> ResolvedIps { get; } = [];
    public bool HasErrors => throw new NotImplementedException();
    public AvaloniaList<string> Warnings { get; set; } = [];

    public async Task CheckFirewallRules()
    {
        errorMessages.Clear();
        ResolvedIps.Clear();
        Warnings.Clear();

        var sourceIpValidationResult = await ValidateIpAddress(Source);
        (IEnumerable<uint?>? numericSourceIps, bool sourceIpDnsResolved) = sourceIpValidationResult.Match(
            errors => 
            {
                errorMessages[nameof(Source)] = errors;
                return (null!, false);
            },
            bytes => bytes
        );

        var destinationPortValidationResult = ValidatePort(DestinationPort);
        var destinationPort = destinationPortValidationResult.Match(
            errors =>
            {
                errorMessages[nameof(DestinationPort)] = errors;
                return null;
            },
            port => port
        );

        var validNetworkProtocol = Enum.TryParse<NetworkProtocols>(SelectedProtocol, out var networkProtocol);
        var validApplicationProtocol = Enum.TryParse<ApplicationProtocol>(SelectedProtocol, out var applicationProtocol);
        if (!validNetworkProtocol && !validApplicationProtocol)
        {
            errorMessages[nameof(SelectedProtocol)] = new List<string> { "Value is required" };
        }

        IEnumerable<uint?>? numericDestinationIps = [];
        bool destinationDnsResolved = false;

        var destinationIpValidationResult = await ValidateIpAddress(Destination, allowUnresolvable: validApplicationProtocol);
        (numericDestinationIps, destinationDnsResolved) = destinationIpValidationResult.Match(
            errors => 
            {
                errorMessages[nameof(Destination)] = errors;
                return (null!, false);
            },
            bytes => bytes
        );

        SetErrors(nameof(Source), nameof(DestinationPort), nameof(Destination), nameof(SelectedProtocol));

        if (Firewall == null || errorMessages.Count != 0 || numericSourceIps == null || numericDestinationIps == null 
            || (!validNetworkProtocol && !validApplicationProtocol))
        {
            return;
        }

        Dispatcher.UIThread.Invoke(() =>
        {
            if (sourceIpDnsResolved && (numericSourceIps?.Any() ?? false))
            {
                IPAddress[] convertedIps = numericSourceIps.Select(item => item?.ConvertToIpAddress()).Where(item => item != null).ToArray()!;
                ResolvedIps.Add(new ResolvedDns(Source, convertedIps));
            }
            if (destinationDnsResolved && (numericDestinationIps?.Any() ?? false))
            {
                IPAddress[] convertedIps = numericDestinationIps.Select(item => item?.ConvertToIpAddress()).Where(item => item != null).ToArray()!;
                ResolvedIps.Add(new ResolvedDns(Destination, convertedIps));
            }
            RuleProcessingResponses.Clear();
        });

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);

        var responsesTask = networkProtocol == NetworkProtocols.None
            ? SearchApplicationRules(
                numericSourceIps: numericSourceIps,
                destinationFqdn: Destination,
                portProtocol: new ApplicationProtocolPort(applicationProtocol, destinationPort),
                ruleProcessor: ruleProcessor
            )
            : SearchNetworkRules(
                numericSourceIps: numericSourceIps,
                numericDestinationIps: numericDestinationIps,
                destinationPort: destinationPort,
                protocol: networkProtocol,
                ruleProcessor: ruleProcessor
            );

        var results = await responsesTask;
        Dispatcher.UIThread.Invoke(() =>
        {
            if (validNetworkProtocol && destinationPort != null && results.Any(item => item is ApplicationProcessingResponse))
            {
                Warnings.Add(@"Warning: This request matched an application rule on a non-standard port.  If this request is not handled by a network rule first, it will be processed using the application protocol of that application rule, regardless of destination IP or FQDN.
If that is not the correct protocol, application errors are likely and the traffic may not appear correctly in the logs.");
            }

            if (!results.Any())
            {
                Warnings.Add($"No rules matched {SelectedProtocol} from {Source} to {Destination}:{DestinationPort}");
            }

            RuleProcessingResponses.AddRange(results);
        });
    }

    public static async Task<IEnumerable<ProcessingResponseBase>> SearchApplicationRules(
        IEnumerable<uint?> numericSourceIps,
        string destinationFqdn, 
        ApplicationProtocolPort portProtocol, 
        RuleProcessor ruleProcessor)
    {
        var requests = numericSourceIps.Select(item => new ApplicationRequest(item, destinationFqdn, portProtocol));
        var responses = (await Task.WhenAll(requests.Select(ruleProcessor.ProcessApplicationRequest))).SelectMany(item => item);
        return responses;
    }

    public static async Task<IEnumerable<ProcessingResponseBase>> SearchNetworkRules(
        IEnumerable<uint?> numericSourceIps,
        IEnumerable<uint?> numericDestinationIps,
        ushort? destinationPort,
        NetworkProtocols protocol,
        RuleProcessor ruleProcessor)
    {
        var requests = numericSourceIps
            .SelectMany(numericSourceIp => numericDestinationIps
                .Select(numericDestinationIp => new NetworkRequest(numericSourceIp, numericDestinationIp, destinationPort, protocol)));
        var results = await ruleProcessor.ProcessNetworkRequests(requests.ToArray());
        return results;
    }

    private static OneOf<List<string>, ushort?> ValidatePort(string port)
    {
        if (ushort.TryParse(port, out var parsedPort))
        {
            return parsedPort;
        }
        else if (port == "*")
        {
            return (ushort?)null;
        }

        return new List<string>() { $"Must be a number between 1 and {ushort.MaxValue}, or a *" };
    }

    private async Task<OneOf<List<string>, (IEnumerable<uint?> ipBytes, bool dnsResolved)>> ValidateIpAddress(string ipAddressValue, bool allowUnresolvable = false)
    {
        var errors = new List<string>();

        if (IPAddress.TryParse(ipAddressValue, out var ipAddress))
        {
            var bytes = new uint?[] { ipAddress.ConvertToUint() };
            return OneOf<List<string>, (IEnumerable<uint?>, bool)>.FromT1((bytes, false));
        }
        else if (string.IsNullOrWhiteSpace(ipAddressValue))
        {
            errors.Add("Please supply a value");
            return errors;
        }
        IEnumerable<uint?> resolvedIps = ipAddressValue == "*" 
            ? []
            : (await DnsResolver.ResolveAddress(ipAddressValue)).Cast<uint?>() ?? new List<uint?>();
        if (resolvedIps.Any() || allowUnresolvable)
        {
            return OneOf<List<string>, (IEnumerable<uint?>, bool)>.FromT1((resolvedIps, true));
        }
        else if (ipAddressValue == "*")
        {
            return OneOf<List<string>, (IEnumerable<uint?>, bool)>.FromT1((new List<uint?> { null }, false));
        }
        else
        {
            errors.Add("Value must be a wildcard, a valid IP, or resolve to a valid IP");
        }


        return errors;
    }

    public IEnumerable GetErrors(string? propertyName)
    {
        return errorMessages.TryGetValue(propertyName ?? string.Empty, out var errors) 
            ? errors 
            : Array.Empty<string>();
    }

    public void SetErrors(params string[] propertyNames)
    {
        foreach (var property in propertyNames)
        {
            ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(property));
        }
    }
}