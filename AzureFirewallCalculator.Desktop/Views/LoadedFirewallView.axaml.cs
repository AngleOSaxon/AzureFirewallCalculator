using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class LoadedFirewallView : ReactiveUserControl<LoadedFirewallViewModel>, IViewFor<LoadedFirewallViewModel>, IViewFor
{
    public LoadedFirewallView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }

    public async void TabStripItem_CheckTrafficClicked(object sender, PointerReleasedEventArgs args)
    {
        await this.ViewModel!.NavigateTo(CheckTrafficViewModel.CheckTrafficUrlPathSegment);
    }

    public async void TabStripItem_RuleOverlapClicked(object sender, PointerReleasedEventArgs args)
    {
        await this.ViewModel!.NavigateTo(RuleOverlapViewModel.RuleOverlapUrlPathSegment);
    }
}