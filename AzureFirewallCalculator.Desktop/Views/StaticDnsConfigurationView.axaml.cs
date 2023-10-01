using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class StaticDnsConfigurationView : ReactiveUserControl<StaticDnsConfigurationViewModel>, IViewFor<StaticDnsConfigurationViewModel>, IViewFor
{
    public StaticDnsConfigurationView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}