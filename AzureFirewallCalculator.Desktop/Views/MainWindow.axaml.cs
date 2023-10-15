using System;
using System.Collections.Specialized;
using System.Reactive.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.ReactiveUI;
using Avalonia.Threading;
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
        // TODO: Review to make sure is disposed properly and doesn't leak
        // Though this view is currently expected to live for the lifetime of the app
        _ = Observable.FromEventPattern<NotifyCollectionChangedEventArgs>(logView!.Items, nameof(logView.Items.CollectionChanged)) // TODO: Can I do this with a direct reference and not a string?
            .Throttle(TimeSpan.FromMilliseconds(500))
            .Subscribe(e =>
            {
                Dispatcher.UIThread.Invoke(() =>
                {
                    var scrollViewer = logView!.FindDescendantOfType<ScrollViewer>();
                    scrollViewer!.ScrollToEnd();
                });
            });
    }
}