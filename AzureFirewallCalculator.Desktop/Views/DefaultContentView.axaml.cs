using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class DefaultContentView : ReactiveUserControl<DefaultContentViewModel>, IViewFor<DefaultContentViewModel>, IViewFor
{
    public DefaultContentView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}