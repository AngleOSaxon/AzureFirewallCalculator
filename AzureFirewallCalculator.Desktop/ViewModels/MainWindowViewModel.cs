using Avalonia.Collections;
using AzureFirewallCalculator.Core.ArmSource;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Desktop.Authentication;
using AzureFirewallCalculator.Desktop.FileImports;
using AzureFirewallCalculator.Desktop.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using ReactiveUI;
using System.Linq;
using System.Reactive;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class MainWindowViewModel : ViewModelBase, IScreen
{
    public RoutingState Router { get; } = new RoutingState();

    public ReactiveCommand<Unit, IRoutableViewModel> GoToLoadFromArm { get; }
    public ReactiveCommand<Unit, IRoutableViewModel> GoToLoadFromFiles { get; }

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

    public AvaloniaList<LogData> Logs { get; } = new AvaloniaList<LogData>();

    public MainWindowViewModel(AuthenticationService authenticationService, FileService fileService, IDnsResolver dnsResolver, InMemoryLogReader inMemoryLogReader, ArmService armService, ILoggerFactory loggerFactory)
    {
        GoToLoadFromArm = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromArmViewModel(this, dnsResolver, authenticationService, armService)));
        GoToLoadFromFiles = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromFileViewModel(this, dnsResolver, fileService, loggerFactory)));
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
            Logs.Add(log);
        };
    }
}