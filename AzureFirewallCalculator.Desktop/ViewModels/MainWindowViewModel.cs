using Avalonia.Collections;
using AzureFirewallCalculator.Core.ArmSource;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Desktop.Authentication;
using AzureFirewallCalculator.Desktop.FileImports;
using AzureFirewallCalculator.Desktop.Logging;
using AzureFirewallCalculator.Desktop.Views;
using DynamicData;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using ReactiveUI;
using Splat;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class MainWindowViewModel : ViewModelBase, IScreen
{
    public RoutingState Router { get; } = new RoutingState();

    public ReactiveCommand<Unit, IRoutableViewModel> GoToLoadFromArm { get; }
    public ReactiveCommand<Unit, IRoutableViewModel> GoToLoadFromFiles { get; }
    public ReactiveCommand<Unit, IRoutableViewModel> GoToStaticDnsConfiguration { get; }
    public ReactiveCommand<string, Unit> FilterLogsCommand { get; }

    public bool ErrorFilterActive => (FilteredLogLevels & (1<<((int)LogLevel.Error))) == 0;    
    public bool InformationFilterActive => (FilteredLogLevels & (1<<((int)LogLevel.Information))) == 0;    
    public bool WarningFilterActive => (FilteredLogLevels & (1<<((int)LogLevel.Warning))) == 0;    
    public bool DebugFilterActive => (FilteredLogLevels & (1<<((int)LogLevel.Debug))) == 0;    

    private const string DEFAULT_USERNAME_TEXT = "Not logged in";
    private string userName = DEFAULT_USERNAME_TEXT;
    public string UserName
    {
        get { return userName; }
        set
        {
            this.RaiseAndSetIfChanged(ref userName, value);
        }
    }

    public AvaloniaList<LogData> Logs { get; }

    private bool FilterLogs(LogData log)
    {
        if (log == null)
        {
            return false;
        }
        var result = FilteredLogLevels & (ushort)(1<<((int)log.LogLevel));
        return result > 0;
    }

    private ushort FilteredLogLevels = ushort.MaxValue ^ (1<<((int)LogLevel.Information));

    public MainWindowViewModel(AuthenticationService authenticationService, FileService fileService, CachingResolver dnsResolver, InMemoryLogReader inMemoryLogReader, ArmService armService, ILoggerFactory loggerFactory)
    {
        GoToLoadFromArm = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromArmViewModel(this, dnsResolver, authenticationService, armService, loggerFactory.CreateLogger<LoadFromArmViewModel>())));
        GoToLoadFromFiles = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromFileViewModel(this, dnsResolver, fileService, loggerFactory.CreateLogger<LoadFromFileViewModel>(), loggerFactory)));
        GoToStaticDnsConfiguration = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new StaticDnsConfigurationViewModel(this, Locator.Current.GetService<StaticDnsResolver>()!, loggerFactory.CreateLogger<StaticDnsConfigurationViewModel>())));
        Logs = new AvaloniaList<LogData>(inMemoryLogReader.GetLogView(100_000).Where(FilterLogs));

        FilterLogsCommand = ReactiveCommand.Create((string logLevel) =>
        {
            var level = Enum.Parse<LogLevel>(logLevel);
            FilteredLogLevels ^= (ushort)(1<<((int)level));
            Logs.Clear();
            Logs.AddRange(inMemoryLogReader.GetLogView(100_000).Where(FilterLogs));
            this.RaisePropertyChanged(nameof(ErrorFilterActive));
            this.RaisePropertyChanged(nameof(InformationFilterActive));
            this.RaisePropertyChanged(nameof(WarningFilterActive));
            this.RaisePropertyChanged(nameof(DebugFilterActive));
        });

        authenticationService.UserLogin += (source, account) =>
        {
            var homeTenant = account.GetTenantProfiles().FirstOrDefault(item => item.IsHomeTenant);
            if (homeTenant?.ClaimsPrincipal.Identity is not System.Security.Claims.ClaimsIdentity identity)
            {
                return;
            }
            
            var nameClaim = identity.Claims.FirstOrDefault(item => item.Type == "name");
            if (nameClaim == null)
            {
                return;
            }

            UserName = nameClaim.Value ?? DEFAULT_USERNAME_TEXT;
        };

        inMemoryLogReader.LogPosted += (source, log) =>
        {
            if (FilterLogs(log))
            {
                Logs.Add(log);
            }
        };
    }
}