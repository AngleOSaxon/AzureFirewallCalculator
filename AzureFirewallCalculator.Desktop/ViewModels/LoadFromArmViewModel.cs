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
using Microsoft.Extensions.Logging;
using Azure.Core;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class LoadFromArmViewModel : ReactiveObject, IRoutableViewModel, IScreen
{
    public IScreen HostScreen { get; }
    public IDnsResolver DnsResolver { get; }
    public AuthenticationService AuthenticationService { get; }
    public string UrlPathSegment { get; } = "load-from-arm";
    public ArmService ArmService { get; }
    public ILogger<LoadFromArmViewModel> Logger { get; }
    public AvaloniaList<SubscriptionResource> Subscriptions { get; }
    private SubscriptionResource? subscription;
    private Task subscriptionSelecting = Task.CompletedTask;
    public SubscriptionResource? Subscription 
    { 
        get => subscription;
        set
        {
            this.RaiseAndSetIfChanged(ref subscription, value);
            if (value == null)
            {
                return;
            }

            subscriptionSelecting = SubscriptionSelected(value);
        }
    }
    public AvaloniaList<AzureFirewallData> Firewalls { get; }
    private AzureFirewallData? firewall;
    private Task firewallSelecting = Task.CompletedTask;
    public AzureFirewallData? Firewall
    {
        get => firewall;
        set
        {
            this.RaiseAndSetIfChanged(ref firewall, value);
            if (value == null)
            {
                return;
            }

            firewallSelecting = FirewallSelected(value);
        }
    }
    public Firewall? ConvertedFirewall { get; set; }
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
    private bool controlsDisabled;
    public bool ControlsDisabled
    {
        get { return controlsDisabled; }
        set { this.RaiseAndSetIfChanged(ref controlsDisabled, value); }
    }
    
    public ReactiveCommand<Unit, Task> LoginCommand { get; }    
    
    public LoadFromArmViewModel(IScreen screen, IDnsResolver dnsResolver, AuthenticationService authenticationService, ArmService armService, ILogger<LoadFromArmViewModel> logger)
    {
        HostScreen = screen;
        DnsResolver = dnsResolver;
        AuthenticationService = authenticationService;
        ArmService = armService;
        Logger = logger;
        Subscriptions = [];
        Firewalls = [];
        LoginCommand = ReactiveCommand.CreateFromObservable(() => Observable.Start(() => LoadSubscriptions()));
        _ = Init();
    }

    public async Task Init()
    {
        await AuthenticationService.Init();

        if (!await AuthenticationService.IsUserLoggedIn())
        {
            return;
        }

        UserLoggedIn = true;
        await LoadSubscriptions();

        Subscription = ArmService.SelectedSubscription;
        // Make sure the firewalls have been reloaded before selecting the firewall
        await subscriptionSelecting;
        Firewall = ArmService.SelectedFirewall;
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
        ArmService.SelectedSubscription = subscription;
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
            Logger.LogInformation("Unable to load firewall. {nullResource} was null", Subscription == null ? nameof(Subscription) : nameof(firewall));
            return;
        }

        ArmService.SelectedFirewall = firewall;

        await Load("Loading firewall...", async () =>
        {
            var ipGroups = await ArmService.GetIpGroups(firewall);
            var serviceTags = await ArmService.GetServiceTags(Subscription, firewall.Location);

            serviceTags ??= await Core.Tags.ServiceTagImporter.GetServiceTags(DateTimeOffset.UtcNow);

            if (serviceTags == null)
            {
                Logger.LogError("Unable to load service tags.  Rules using service tags will not be processed properly.");
            }

            ConvertedFirewall = await ArmService.ConvertToFirewall(firewall, ipGroups, serviceTags ?? Array.Empty<ServiceTag>());
            await Router.NavigateAndReset.Execute(new CheckTrafficViewModel(ConvertedFirewall, DnsResolver, this));
        });
    }

    public async Task ReloadData()
    {
        var subscriptionId = Subscription?.Data.SubscriptionId;
        var firewallId = Firewall?.Id;

        Subscription = null;
        Firewall = null;
        ConvertedFirewall = null;

        ArmService.ResetCache();

        await LoadSubscriptions();

        Subscription = Subscriptions.FirstOrDefault(item => item.Data.SubscriptionId == subscriptionId);
        if (Subscription == null)
        {
            return;
        }

        await subscriptionSelecting;

        Firewall = Firewalls.FirstOrDefault(item => item.Id == (firewallId ?? ResourceIdentifier.Root));
        if (Firewall == null)
        {
            return;
        }

        await firewallSelecting;
    }

    private async Task Load(string text, Func<Task> action)
    {
        var cancellationTokenSource = new CancellationTokenSource();
        LoadIndicatorText = text;
        ShowLoadIndicator = true;
        _ = ChangeLoadIndicator(cancellationTokenSource.Token);
        ControlsDisabled = true;
        try
        {
            await action();
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Error while loading: {errorMessage}", e.Message);
        }
        finally
        {
            ShowLoadIndicator = false;
            cancellationTokenSource.Cancel();
            LoadIndicatorText = "Loading...";
            ControlsDisabled = false;
        }
    }
}