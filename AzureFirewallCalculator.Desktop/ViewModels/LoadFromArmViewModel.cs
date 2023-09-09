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

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class LoadFromArmViewModel : ReactiveObject, IRoutableViewModel, IScreen
{
    public IScreen HostScreen { get; }
    public string UrlPathSegment { get; } = "load-from-arm";
    public IPublicClientApplication IdentityClient { get; }
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

    public LoadFromArmViewModel(IScreen screen)
    {
        HostScreen = screen;
        IdentityClient = PublicClientApplicationBuilder.Create("5fb5bdf1-9e6f-4a5a-a0cd-390f7fe43ec9")
            .WithAuthority(AzureCloudInstance.AzurePublic, "common")
            .WithRedirectUri("http://localhost")
            .Build();
        var token = new AuthenticationToken(IdentityClient);
        
        Resolver = new DynamicResolver();
        ArmService = new ArmService(new ArmClient(token), Resolver);
        Subscriptions = new AvaloniaList<SubscriptionResource>();
        Firewalls = new AvaloniaList<AzureFirewallData>();
        _ = LoadSubscriptions();
    }

    public async Task LoadSubscriptions()
    {
        Subscriptions.Clear();
        var collection = await ArmService.GetSubscriptions();
        foreach (var subscription in collection)
        {
            Subscriptions.Add(subscription);
        }
    }

    public async Task SubscriptionSelected(SubscriptionResource subscription)
    {
        Firewalls.Clear();
        var firewalls = await ArmService.GetFirewalls(subscription);
        foreach (var firewall in firewalls)
        {
            Firewalls.Add(firewall);
        }
    }

    public async Task FirewallSelected(AzureFirewallData firewall)
    {
        if (firewall?.Location == null || Subscription == null)
        {
            return;
        }

        var ipGroups = await ArmService.GetIpGroups(firewall);
        var serviceTags = await ArmService.GetServiceTags(Subscription, firewall.Location);

        if (serviceTags == null)
        {
            return;
        }

        ConvertedFirewall = await ArmService.ConvertToFirewall(firewall, ipGroups, serviceTags);
        await Router.Navigate.Execute(new CheckTrafficViewModel(ConvertedFirewall, Resolver, this));
    }
}