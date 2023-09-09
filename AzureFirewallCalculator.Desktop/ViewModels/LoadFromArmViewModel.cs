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
    public AuthenticationService AuthenticationService { get; }
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
    private bool userLoggedIn;
    public bool UserLoggedIn
    {
        get { return userLoggedIn; }
        set { this.RaiseAndSetIfChanged(ref userLoggedIn, value); }
    }
    public ReactiveCommand<Unit, Task> LoginCommand { get; }    
    

    public LoadFromArmViewModel(IScreen screen, AuthenticationService authenticationService)
    {
        HostScreen = screen;
        AuthenticationService = authenticationService;
        Resolver = new DynamicResolver();
        ArmService = new ArmService(new ArmClient(authenticationService.GetAuthenticationToken()), Resolver);
        Subscriptions = new AvaloniaList<SubscriptionResource>();
        Firewalls = new AvaloniaList<AzureFirewallData>();
        LoginCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => LoadSubscriptions()));
        _ = Init();
    }

    public async Task Init()
    {
        if (!await AuthenticationService.IsUserLoggedIn())
        {
            return;
        }

        UserLoggedIn = true;
        await LoadSubscriptions();
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
            await Dispatcher.UIThread.InvokeAsync(async () => await Router.NavigateAndReset.Execute(new DefaultContentViewModel(this)));
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
            await Router.NavigateAndReset.Execute(new CheckTrafficViewModel(ConvertedFirewall, Resolver, this));
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