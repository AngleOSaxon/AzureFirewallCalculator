using ReactiveUI;
using System.Reactive;

namespace AzureFirewallCalculator.Desktop.ViewModels;

public class MainWindowViewModel : ViewModelBase, IScreen
{
    public string Greeting => "Welcome to Avalonia!";

    public RoutingState Router { get; } = new RoutingState();

    public ReactiveCommand<Unit, IRoutableViewModel> GoToLoadFromArm { get; }

    public MainWindowViewModel()
    {
        GoToLoadFromArm = ReactiveCommand.CreateFromObservable(() => Router.Navigate.Execute(new LoadFromArmViewModel(this)));
    }
}