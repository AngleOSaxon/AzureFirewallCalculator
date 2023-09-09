using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class DefaultContentViewModel : ReactiveObject, IRoutableViewModel
{
    public DefaultContentViewModel(IScreen hostScreen)
    {
        HostScreen = hostScreen;
    }

    public string? UrlPathSegment => "home";

    public IScreen HostScreen { get; }
}