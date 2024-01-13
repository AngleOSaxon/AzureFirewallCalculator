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
using Avalonia.Input;
using System.Windows.Input;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public record struct ResolvedDns(string Fqdn, IPAddress[] Addresses);

public class CheckTrafficViewModel : ReactiveObject, IRoutableViewModel, INotifyDataErrorInfo
{
    public CheckTrafficViewModel(Firewall? firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;
        CheckNetworkRuleCommand = ReactiveCommand.Create(() => CheckNetworkRule());
        CheckApplicationRuleCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => CheckApplicationRule()));
    }

    private readonly Dictionary<string, IEnumerable<string>> errorMessages = new(StringComparer.CurrentCultureIgnoreCase);
    public Firewall? Firewall { get; set; }
    public IDnsResolver DnsResolver { get; }
    public string NetworkSourceIp { get; set; } = string.Empty;
    public string NetworkDestinationIp { get; set; } = string.Empty;
    public NetworkProtocols[] SelectableNetworkProtocols { get; } = [NetworkProtocols.TCP, NetworkProtocols.UDP, NetworkProtocols.ICMP];
    public NetworkProtocols NetworkProtocol { get; set; } 
    public string NetworkDestinationPort { get; set; } = string.Empty;
    public string ApplicationSourceIp { get; set; } = string.Empty;
    public string DestinationFqdn { get; set; } = string.Empty;
    public ApplicationProtocol[] SelectableApplicationProtocols { get; } = [Core.ApplicationProtocol.Mssql, Core.ApplicationProtocol.Https, Core.ApplicationProtocol.Http];
    public ApplicationProtocol? ApplicationProtocol { get; set; } 
    public string ApplicationDestinationPort { get; set; } = string.Empty;
    // Use Object list to stop cast exceptions when the Selected event fires.  Jesus.
    public AvaloniaList<object> RuleProcessingResponses { get; set; } = [];
    public ReactiveCommand<Unit, Unit> CheckNetworkRuleCommand { get; }
    public ReactiveCommand<Unit, Task> CheckApplicationRuleCommand { get; }
    public string? UrlPathSegment => "check-traffic";
    public IScreen HostScreen { get; }
    public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;
    public AvaloniaList<ResolvedDns> ResolvedIps { get; } = [];
    public bool HasErrors => throw new NotImplementedException();

    public async void CheckNetworkRule()
    {
        errorMessages.Clear();
        ResolvedIps.Clear();

        var sourceIpValidationResult = await ValidateIpAddress(NetworkSourceIp);
        (IEnumerable<uint?>? numericSourceIps, bool sourceIpDnsResolved) = sourceIpValidationResult.Match(
            errors => 
            {
                errorMessages[nameof(NetworkSourceIp)] = errors;
                return (null!, false);
            },
            bytes => bytes
        );

        var destinationIpValidationResult = await ValidateIpAddress(NetworkDestinationIp);
        (IEnumerable<uint?>? numericDestinationIps, bool destinationDnsResolved) = destinationIpValidationResult.Match(
            errors => 
            {
                errorMessages[nameof(NetworkDestinationIp)] = errors;
                return (null!, false);
            },
            bytes => bytes
        );

        var destinationPortValidationResult = ValidatePort(NetworkDestinationPort);
        var destinationPort = destinationPortValidationResult.Match(
            errors =>
            {
                errorMessages[nameof(NetworkDestinationPort)] = errors;
                return null;
            },
            port => port
        );

        if (NetworkProtocol == NetworkProtocols.None)
        {
            errorMessages[nameof(NetworkProtocol)] = new List<string> { "Value is required" };
        }

        SetErrors(nameof(NetworkSourceIp), nameof(NetworkDestinationPort), nameof(NetworkDestinationIp), nameof(NetworkProtocol));

        if (Firewall == null || errorMessages.Count != 0 || numericSourceIps == null || numericDestinationIps == null)
        {
            return;
        }

        Dispatcher.UIThread.Invoke(() =>

        {
            if (sourceIpDnsResolved && numericSourceIps != null)
            {
                IPAddress[] convertedIps = numericSourceIps.Select(item => item?.ConvertToIpAddress()).Where(item => item != null).ToArray()!;
                ResolvedIps.Add(new ResolvedDns(NetworkSourceIp, convertedIps));
            }
            if (destinationDnsResolved && numericDestinationIps != null)
            {
                IPAddress[] convertedIps = numericDestinationIps.Select(item => item?.ConvertToIpAddress()).Where(item => item != null).ToArray()!;
                ResolvedIps.Add(new ResolvedDns(NetworkDestinationIp, convertedIps));
            }
            RuleProcessingResponses.Clear();
        });

        var requests = numericSourceIps.SelectMany(numericSourceIp => numericDestinationIps.Select(numericDestinationIp => new NetworkRequest(numericSourceIp, numericDestinationIp, destinationPort, NetworkProtocol)));

        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        var results = await ruleProcessor.ProcessNetworkRequests(requests.ToArray());
        Dispatcher.UIThread.Invoke(() =>
        {
            RuleProcessingResponses.AddRange(results);
        });
    }

    public async Task CheckApplicationRule()
    {
        errorMessages.Clear();

        var sourceIpValidationResult = await ValidateIpAddress(ApplicationSourceIp);
        (IEnumerable<uint?>? numericSourceIps, bool sourceIpDnsResolved) = sourceIpValidationResult.Match(
            errors => 
            {
                errorMessages[nameof(ApplicationSourceIp)] = errors;
                return (null!, false);
            },
            bytes => bytes
        );

        var destinationPortValidationResult = ValidatePort(ApplicationDestinationPort);
        var destinationPort = destinationPortValidationResult.Match(
            errors =>
            {
                errorMessages[nameof(ApplicationDestinationPort)] = errors;
                return null;
            },
            port => port
        );

        if (string.IsNullOrWhiteSpace(DestinationFqdn))
        {
            errorMessages[nameof(DestinationFqdn)] = new List<string> { "Value is required" };
        }

        if (ApplicationProtocol == null)
        {
            errorMessages[nameof(ApplicationProtocol)] = new List<string> { "Value is required" };
        }

        SetErrors(nameof(ApplicationSourceIp), nameof(ApplicationDestinationPort), nameof(DestinationFqdn), nameof(ApplicationProtocol));

        if (Firewall == null || errorMessages.Count != 0 || numericSourceIps == null)
        {
            return;
        }

        Dispatcher.UIThread.Invoke(() =>
        {
            if (sourceIpDnsResolved && numericSourceIps != null)
            {
                IPAddress[] convertedIps = numericSourceIps.Select(item => item?.ConvertToIpAddress()).Where(item => item != null).ToArray()!;
                ResolvedIps.Add(new ResolvedDns(ApplicationSourceIp, convertedIps));
            }
            RuleProcessingResponses.Clear();
        });

        var portProtocol = new ApplicationProtocolPort(ApplicationProtocol!.Value, destinationPort);
        var requests = numericSourceIps.Select(item => new ApplicationRequest(item, DestinationFqdn, portProtocol));
        var ruleProcessor = new RuleProcessor(DnsResolver, Firewall);
        var responses = (await Task.WhenAll(requests.Select(ruleProcessor.ProcessApplicationRequest))).SelectMany(item => item);

        Dispatcher.UIThread.Invoke(() =>
        {
            RuleProcessingResponses.AddRange(responses);
        });
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

    private async Task<OneOf<List<string>, (IEnumerable<uint?> ipBytes, bool dnsResolved)>> ValidateIpAddress(string ipAddressValue)
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
        if (resolvedIps.Any())
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