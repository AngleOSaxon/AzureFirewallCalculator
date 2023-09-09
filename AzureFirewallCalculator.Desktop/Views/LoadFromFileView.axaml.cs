using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class LoadFromFileView : ReactiveUserControl<LoadFromFileViewModel>, IViewFor<LoadFromFileViewModel>, IViewFor
{
    public LoadFromFileView()
    {
        this.WhenActivated(disposables => {});
        AvaloniaXamlLoader.Load(this);
    }
}