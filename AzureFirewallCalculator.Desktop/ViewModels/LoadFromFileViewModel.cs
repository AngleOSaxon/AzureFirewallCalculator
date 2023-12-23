using System.Reactive;
using System.Threading.Tasks;
using AzureFirewallCalculator.Core.Tags;
using AzureFirewallCalculator.Core.PowershellSource;
using AzureFirewallCalculator.Desktop.FileImports;
using ReactiveUI;
using AzureFirewallCalculator.Core.Dns;
using System.Linq;
using System;
using System.Threading;
using System.Text.Json;
using Avalonia.Threading;
using System.Net;
using System.Reflection;
using Avalonia.Platform;
using Microsoft.Extensions.Logging;
using AzureFirewallCalculator.Core;
using Firewall = AzureFirewallCalculator.Core.PowershellSource.Firewall;
using AzureFirewallCalculator.Core.Serialization;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class LoadFromFileViewModel : ReactiveObject, IRoutableViewModel, IScreen
{
    public LoadFromFileViewModel(IScreen hostScreen, CachingResolver dnsResolver, FileService fileService, ILogger<LoadFromFileViewModel> logger, ILoggerFactory loggerFactory)
    {
        HostScreen = hostScreen;
        DnsResolver = dnsResolver;
        FileService = fileService;
        Logger = logger;
        LoggerFactory = loggerFactory;
        serviceTags = [];
        LoadFirewallCommand = ReactiveCommand.CreateFromTask(() => LoadFirewall());
        LoadIpGroupsCommand = ReactiveCommand.CreateFromTask(() => LoadIpGroups());
        LoadServiceTagsCommand = ReactiveCommand.CreateFromTask(() => LoadServiceTags());
        SaveFirewallExportScriptCommand = ReactiveCommand.CreateFromTask(() => SaveFirewallExportScript());
    }

    public string? UrlPathSegment => "load-from-files";
    public IScreen HostScreen { get; }
    public CachingResolver DnsResolver { get; }
    public FileService FileService { get; }
    public ILogger<LoadFromFileViewModel> Logger { get; }
    public ILoggerFactory LoggerFactory { get; }
    public RoutingState Router { get; } = new RoutingState();
    public ReactiveCommand<Unit, Unit> LoadFirewallCommand { get; }
    public ReactiveCommand<Unit, Unit> LoadIpGroupsCommand { get; }
    public ReactiveCommand<Unit, Unit> LoadServiceTagsCommand { get; }
    public ReactiveCommand<Unit, Unit> SaveFirewallExportScriptCommand { get; }
    private string? firewallFileName;
    public string? FirewallFileName
    {
        get { return firewallFileName; }
        set { this.RaiseAndSetIfChanged(ref firewallFileName, value); }
    }
    private string? ipGroupsFileName;
    public string? IpGroupsFileName
    {
        get { return ipGroupsFileName; }
        set { this.RaiseAndSetIfChanged(ref ipGroupsFileName, value); }
    }
    private Firewall? firewall;
    public Firewall? Firewall
    {
        get { return firewall; }
        set
        {
            this.RaiseAndSetIfChanged(ref firewall, value);
            FirewallLoaded = value != default;
        }
    }
    private bool firewallLoaded;
    public bool FirewallLoaded
    {
        get { return firewallLoaded; }
        set { this.RaiseAndSetIfChanged(ref firewallLoaded, value); }
    }
    private IpGroup[]? ipGroups;
    public IpGroup[]? IpGroups
    {
        get { return ipGroups; }
        set
        {
            this.RaiseAndSetIfChanged(ref ipGroups, value);
            IpGroupsLoaded = value != default;
        }
    }
    private bool ipGroupsLoaded;
    public bool IpGroupsLoaded
    {
        get { return ipGroupsLoaded; }
        set { this.RaiseAndSetIfChanged(ref ipGroupsLoaded, value); }
    }
    private ServiceTag[] serviceTags;
    public ServiceTag[] ServiceTags
    {
        get { return serviceTags; }
        set 
        {
            this.RaiseAndSetIfChanged(ref serviceTags, value);
            ServiceTagsLoaded = value != default;
        }
    }
    private bool serviceTagsLoaded;
    public bool ServiceTagsLoaded
    {
        get { return serviceTagsLoaded; }
        set { this.RaiseAndSetIfChanged(ref serviceTagsLoaded, value); }
    }
    
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
    

    public async Task LoadFirewall()
    {
        await Load("Importing Firewall", async () =>
        {
            var filestream = await FileService.OpenFileAsync("Open Firewall json export");
            if (filestream == null)
            {
                return;
            }
            Firewall = await JsonSerializer.DeserializeAsync(await filestream.OpenReadAsync(), SourceGenerationContext.Default.Firewall);
        });
        
        await CheckAndConvert();
    }

    public async Task LoadIpGroups()
    {
        await Load("Importing IP Groups", async () =>
        {
            var filestream = await FileService.OpenFileAsync("Open IPGroup json export");
            if (filestream == null)
            {
                return;
            }
            IpGroups = await JsonSerializer.DeserializeAsync(await filestream.OpenReadAsync(), SourceGenerationContext.Default.IpGroupArray);
        });
        
        await CheckAndConvert();
    }

    public async Task SaveFirewallExportScript()
    {
        using var scriptStream = Assembly.GetExecutingAssembly().GetManifestResourceStream("AzureFirewallCalculator.Desktop.IncludeScripts.Export-Firewall.ps1")
            ?? throw new Exception("Unable to find embedded script file for export");
        await FileService.SaveFileAsync(
            prompt: "Save script file",
            fileName: "Export-Firewall",
            extension: "ps1",
            fileStream: scriptStream
        );
    }

    public async Task LoadServiceTags()
    {
        await Load("Downloading service tags", async () =>
        {
            ServiceTags = await ServiceTagImporter.GetServiceTags(DateTimeOffset.UtcNow);
        });
        
        await CheckAndConvert();
    }

    private async Task CheckAndConvert()
    {
        if (ipGroups == null || firewall == null || serviceTags == null)
        {
            Logger.LogInformation("Unable to load firewall. {nullResource} was null", ipGroups == null 
                ? "IPGroups"
                : firewall == null
                    ? "Firewall"
                    : "ServiceTags");
            return;
        }
        await Load("Importing firewall", async () =>
        {
            var ipGroupDictionary = ipGroups.ToDictionary(item => item.Id, StringComparer.CurrentCultureIgnoreCase);
            var convertedFirewall = await firewall.Value.ConvertToFirewall(ipGroupDictionary, DnsResolver, serviceTags, LoggerFactory.CreateLogger<Firewall>());
            Dispatcher.UIThread.Invoke(() => Router.Navigate.Execute(new CheckTrafficViewModel(convertedFirewall, DnsResolver, this)));
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
        catch (Exception e)
        {
            Logger.LogError(e, "Error loading data: {errorMessage}", e.Message);
        }
        finally
        {
            ShowLoadIndicator = false;
            cancellationTokenSource.Cancel();
            LoadIndicatorText = "Loading...";
        }
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
}