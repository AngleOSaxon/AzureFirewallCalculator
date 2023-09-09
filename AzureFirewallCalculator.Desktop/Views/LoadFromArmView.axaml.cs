using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class LoadFromArmView : ReactiveUserControl<LoadFromArmViewModel>, IViewFor<LoadFromArmViewModel>, IViewFor
{
    public LoadFromArmView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}