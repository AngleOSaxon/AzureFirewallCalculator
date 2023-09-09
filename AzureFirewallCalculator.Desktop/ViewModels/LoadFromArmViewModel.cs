using System;
using System.Threading.Tasks;
using Avalonia.Collections;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Core.ArmSource;
using AzureFirewallCalculator.Desktop.Authentication;
using Microsoft.Identity.Client;
using ReactiveUI;
using System.Linq;
using Azure.ResourceManager.Network;
using AzureFirewallCalculator.Core;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading;
using Avalonia.Threading;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class LoadFromArmViewModel : ReactiveObject, IRoutableViewModel, IScreen
{
    public IScreen HostScreen { get; }
    public string UrlPathSegment { get; } = "load-from-arm";
    public ArmService ArmService { get; }
    public AvaloniaList<SubscriptionResource> Subscriptions { get; }
    private SubscriptionResource? subscription;
    public SubscriptionResource? Subscription 
    { 
        get => subscription;
        set
        {
            subscription = value;
            if (value == null)
            {
                return;
            }

            _ = SubscriptionSelected(value);
        }
    }
    public AvaloniaList<AzureFirewallData> Firewalls { get; }
    private AzureFirewallData? firewall;
    public AzureFirewallData? Firewall
    {
        get => firewall;
        set
        {
            firewall = value;
            if (value == null)
            {
                return;
            }

            _ = FirewallSelected(value);
        }
    }
    public Firewall? ConvertedFirewall { get; set; }
    public IDnsResolver Resolver { get; }
    public RoutingState Router { get; } = new RoutingState();
    private bool showLoadIndicator;
    public bool ShowLoadIndicator
    {
        get { return showLoadIndicator; }
        set { this.RaiseAndSetIfChanged(ref showLoadIndicator, value); }
    }
    private int loadIndicator;
    public int LoadIndicator { get => loadIndicator; set => this.RaiseAndSetIfChanged(ref loadIndicator, value); }
    private string loadIndicatorText = "Loading...";
    public string LoadIndicatorText
    {
        get { return loadIndicatorText; }
        set { this.RaiseAndSetIfChanged(ref loadIndicatorText, value); }
    }
    

    public LoadFromArmViewModel(IScreen screen, AuthenticationService authenticationService)
    {
        HostScreen = screen;
        
        Resolver = new DynamicResolver();
        ArmService = new ArmService(new ArmClient(authenticationService.GetAuthenticationToken()), Resolver);
        Subscriptions = new AvaloniaList<SubscriptionResource>();
        Firewalls = new AvaloniaList<AzureFirewallData>();
        _ = LoadSubscriptions();
    }

    public async Task LoadSubscriptions()
    {
        Subscriptions.Clear();

        await Load("Logging in...", async () =>
        {
            var collection = await ArmService.GetSubscriptions();
            foreach (var subscription in collection)
            {
                Dispatcher.UIThread.Invoke(() => Subscriptions.Add(subscription));
            }
        });
    }

    private async Task ChangeLoadIndicator(CancellationToken token)
    {
        LoadIndicator = 0;
        while (!token.IsCancellationRequested)
        {
            LoadIndicator = (LoadIndicator + 5) % 100;
            await Task.Delay(100, token);
        }
        LoadIndicator = 0;
    }

    public async Task SubscriptionSelected(SubscriptionResource subscription)
    {
        Firewalls.Clear();
        await Load("Loading firewalls...", async () =>
        {
            var firewalls = await ArmService.GetFirewalls(subscription);
            foreach (var firewall in firewalls)
            {
                Dispatcher.UIThread.Invoke(() => Firewalls.Add(firewall));
            }
        });
    }

    public async Task FirewallSelected(AzureFirewallData firewall)
    {
        if (firewall?.Location == null || Subscription == null)
        {
            return;
        }
        
        await Load("Loading firewall...", async () =>
        {
            var ipGroups = await ArmService.GetIpGroups(firewall);
            var serviceTags = await ArmService.GetServiceTags(Subscription, firewall.Location);

            if (serviceTags == null)
            {
                return;
            }

            ConvertedFirewall = await ArmService.ConvertToFirewall(firewall, ipGroups, serviceTags);
            await Router.Navigate.Execute(new CheckTrafficViewModel(ConvertedFirewall, Resolver, this));
        });
    }

    private async Task Load(string text, Func<Task> action)
    {
        var cancellationTokenSource = new CancellationTokenSource();
        LoadIndicatorText = text;
        ShowLoadIndicator = true;
        _ = ChangeLoadIndicator(cancellationTokenSource.Token);
        try
        {
            await action();
        }
        finally
        {
            ShowLoadIndicator = false;
            cancellationTokenSource.Cancel();
            LoadIndicatorText = "Loading...";
        }
    }
}