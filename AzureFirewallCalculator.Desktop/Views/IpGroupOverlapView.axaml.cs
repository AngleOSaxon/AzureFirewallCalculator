using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class IpGroupOverlapView : ReactiveUserControl<IpGroupOverlapViewModel>, IViewFor<IpGroupOverlapViewModel>, IViewFor
{
    public IpGroupOverlapView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}