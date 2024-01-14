using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class CheckTrafficView : ReactiveUserControl<CheckTrafficViewModel>, IViewFor<CheckTrafficViewModel>, IViewFor
{
    public CheckTrafficView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }

    public async void FirewallRuleSearch(object sender, KeyEventArgs args)
    {
        if (args.Key != Key.Enter || args.Source is ComboBox)
        {
            return;
        }
        await this.ViewModel!.CheckFirewallRules();
    }
}