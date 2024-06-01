using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class RuleOverlapView : ReactiveUserControl<RuleOverlapViewModel>, IViewFor<RuleOverlapViewModel>, IViewFor
{
    public RuleOverlapView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}