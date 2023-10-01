using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using Avalonia.VisualTree;
using AzureFirewallCalculator.Desktop.ViewModels;
using ReactiveUI;

namespace AzureFirewallCalculator.Desktop.Views;

public partial class MainWindow : ReactiveWindow<MainWindowViewModel>
{
    public MainWindow()
    {
        this.WhenActivated(disposables => { });
        AvaloniaXamlLoader.Load(this);
#if DEBUG
        this.AttachDevTools();
#endif
        var logView = this.FindControl<ListBox>("LogView");
        // Null derefs can and should crash us, because should never be null
        logView!.Items.CollectionChanged += (sender, e) =>
        {
            var scrollViewer = logView!.FindDescendantOfType<ScrollViewer>();
            scrollViewer!.ScrollToEnd();
        };
    }
}