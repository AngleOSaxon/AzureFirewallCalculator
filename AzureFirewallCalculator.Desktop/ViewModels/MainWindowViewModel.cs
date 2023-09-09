using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Desktop.Authentication;
using AzureFirewallCalculator.Desktop.FileImports;
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

    public MainWindowViewModel(AuthenticationService authenticationService, FileService fileService, IDnsResolver dnsResolver)
    {
        GoToLoadFromArm = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromArmViewModel(this, dnsResolver, authenticationService)));
        GoToLoadFromFiles = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromFileViewModel(this, dnsResolver, fileService)));
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
    }
}