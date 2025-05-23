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

public class RangeRuleComparisonViewModel : ReactiveObject, IRoutableViewModel, INotifyDataErrorInfo
{
    public RangeRuleComparisonViewModel(Firewall? firewall, IDnsResolver dnsResolver, IScreen hostScreen)
    {
        Firewall = firewall;
        DnsResolver = dnsResolver;
        HostScreen = hostScreen;
        CompareCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => CompareRanges()));
    }

    private readonly Dictionary<string, IEnumerable<string>> errorMessages = new(StringComparer.CurrentCultureIgnoreCase);
    public Firewall? Firewall { get; set; }
    public IDnsResolver DnsResolver { get; }
    public string FirstRange { get; set; } = string.Empty;
    public string SecondRange { get; set; } = string.Empty;
    public const string RangeRuleComparisonUrlPathSegment = "range-rule-comparison";
    public string? UrlPathSegment => RangeRuleComparisonUrlPathSegment;
    public IScreen HostScreen { get; }
    public event EventHandler<DataErrorsChangedEventArgs>? ErrorsChanged;
    public AvaloniaList<ResolvedDns> ResolvedIps { get; } = [];
    public bool HasErrors => errorMessages.Count != 0;
    public AvaloniaList<string> Warnings { get; set; } = [];
    public RoutingState Router { get; } = new RoutingState();
    public ReactiveCommand<Unit, Task> CompareCommand { get; }

    public AvaloniaList<object> FirstRangeOnly { get; set; } = [];
    public AvaloniaList<object> SecondRangeOnly { get; set; } = [];
    public AvaloniaList<object> BothRangesOnly { get; set; } = [];
    
    private AvaloniaList<object> displayedRange = [];
    public AvaloniaList<object> DisplayedRange
    {
        get { return displayedRange; }
        set { this.RaiseAndSetIfChanged(ref displayedRange, value); }
    }

    private string? selectedDisplay;
    public string? SelectedDisplay
    {
        get { return selectedDisplay; }
        set
        {
            this.RaiseAndSetIfChanged(ref selectedDisplay, value); 
            DisplayRange();
        }
    }


    public async Task CompareRanges()
    {
        errorMessages.Clear();
        ResolvedIps.Clear();
        Warnings.Clear();

        FirstRange = FirstRange.Trim();
        SecondRange = SecondRange.Trim();

        var processor = new RuleProcessor(DnsResolver, Firewall);
        
        if (!IPNetwork.TryParse(FirstRange, out var baseRange))
        {
            errorMessages[nameof(FirstRange)] = [ "Invalid CIDR range" ];
        }
        if (!IPNetwork.TryParse(SecondRange, out var comparisonRange))
        {
            errorMessages[nameof(SecondRange)] = [ "Invalid CIDR range" ];
        }

        ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(nameof(FirstRange)));
        ErrorsChanged?.Invoke(this, new DataErrorsChangedEventArgs(nameof(SecondRange)));
        
        if (baseRange == default || comparisonRange == default)
        {
            return;
        }

        var firstRangeRequests = Enumerable.Range(0, baseRange.PrefixLength).Select(offset => new NetworkRequest(
                sourceIp: baseRange.BaseAddress.ConvertToUint() + (uint)offset, 
                destinationIp: null, 
                destinationPort: null, 
                protocol: NetworkProtocols.Any
            )
        );

        var secondRangeRequests = Enumerable.Range(0, comparisonRange.PrefixLength).Select(offset => new NetworkRequest(
                sourceIp: comparisonRange.BaseAddress.ConvertToUint() + (uint)offset, 
                destinationIp: null, 
                destinationPort: null, 
                protocol: NetworkProtocols.Any
            )
        );
        
        var firstResults = await processor.ProcessNetworkRequests(firstRangeRequests);
        var secondResults = await processor.ProcessNetworkRequests(secondRangeRequests);

        var firstRangeNetworkRules = new List<NetworkRule>();
        var firstRangeApplicationRules = new List<ApplicationRule>();
        foreach (var result in firstResults)
        {
            if (result is NetworkProcessingResponse networkResponse)
            {
                firstRangeNetworkRules.AddRange(networkResponse.MatchedRules.Select(item => item.Rule));
            }
            else if (result is ApplicationProcessingResponse applicationResponse)
            {
                firstRangeApplicationRules.AddRange(applicationResponse.MatchedRules.Select(item => item.Rule));
            }
            else
            {
                throw new Exception($"Unexpected processing response type '{result.GetType().FullName}'");
            }
        }

        var secondRangeNetworkRules = new List<NetworkRule>();
        var secondRangeApplicationRules = new List<ApplicationRule>();
        foreach (var result in secondResults)
        {
            if (result is NetworkProcessingResponse networkResponse)
            {
                secondRangeNetworkRules.AddRange(networkResponse.MatchedRules.Select(item => item.Rule));
            }
            else if (result is ApplicationProcessingResponse applicationResponse)
            {
                secondRangeApplicationRules.AddRange(applicationResponse.MatchedRules.Select(item => item.Rule));
            }
            else
            {
                throw new Exception($"Unexpected processing response type '{result.GetType().FullName}'");
            }
        }
        FirstRangeOnly.Clear();
        SecondRangeOnly.Clear();
        BothRangesOnly.Clear();

        var networkRuleComparer = new NetworkRuleComparer();
        var applicationRuleComparer = new ApplicationRuleComparer();

        var firstOnlyNetworkRules = firstRangeNetworkRules.Except(secondRangeNetworkRules, networkRuleComparer);
        var firstOnlyApplicationRules = firstRangeApplicationRules.Except(secondRangeApplicationRules, applicationRuleComparer);

        FirstRangeOnly.AddRange(firstOnlyNetworkRules.Cast<object>().Concat(firstOnlyApplicationRules));

        var secondOnlyNetworkRules = secondRangeNetworkRules.Except(firstRangeNetworkRules, networkRuleComparer);
        var secondOnlyApplicationRules = secondRangeApplicationRules.Except(firstRangeApplicationRules, applicationRuleComparer);

        SecondRangeOnly.AddRange(secondOnlyNetworkRules.Cast<object>().Concat(secondOnlyApplicationRules));

        var combinedNetworkRules = firstRangeNetworkRules.Intersect(secondRangeNetworkRules, networkRuleComparer);
        var combinedApplicationRules = firstRangeApplicationRules.Intersect(secondRangeApplicationRules, applicationRuleComparer);

        BothRangesOnly.AddRange(combinedNetworkRules.Cast<object>().Concat(combinedApplicationRules));
        DisplayRange();
    }

    public void DisplayRange()
    {
        if (SelectedDisplay == null)
        {
            return;
        }
        if (SelectedDisplay == "OnlyFirst")
        {
            DisplayedRange = FirstRangeOnly;
        }
        else if (SelectedDisplay == "OnlySecond")
        {
            DisplayedRange = SecondRangeOnly;
        }
        else if (SelectedDisplay == "OnlyBoth")
        {
            DisplayedRange = BothRangesOnly;
        }
        else
        {
            throw new Exception($"Unexpected 'SelectedDisplay' value of '{SelectedDisplay}'");
        }
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

    public async Task NavigateTo(string tabName)
    {
        if (tabName == Router.NavigationStack.Last().UrlPathSegment)
        {
            return;
        }

        await Router.NavigateBack.Execute();
        IRoutableViewModel newDestination = tabName switch
        {
            // CheckTrafficViewModel.CheckTrafficUrlPathSegment => new CheckTrafficViewModel(Firewall, DnsResolver, this),
            _ => throw new InvalidOperationException($"Unknown view '{tabName}'"),
        };
        await Router.Navigate.Execute(newDestination);
    }

    public IEnumerable GetErrors(string? propertyName)
    {
        return errorMessages.TryGetValue(propertyName ?? string.Empty, out var errors) 
            ? errors 
            : Array.Empty<string>();
    }
}