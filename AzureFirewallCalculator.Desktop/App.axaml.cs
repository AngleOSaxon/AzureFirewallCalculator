using System.Reflection;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using AzureFirewallCalculator.Desktop.ViewModels;
using AzureFirewallCalculator.Desktop.Views;
using ReactiveUI;
using Splat;

namespace AzureFirewallCalculator.Desktop;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(),
            };
        }

        Locator.CurrentMutable.RegisterViewsForViewModels(Assembly.GetCallingAssembly());
        Locator.CurrentMutable.Register(() => new LoadFromArmView(), typeof(IViewFor<LoadFromArmViewModel>));
        Locator.CurrentMutable.Register(() => new CheckTrafficView(), typeof(IViewFor<CheckTrafficViewModel>));

        base.OnFrameworkInitializationCompleted();
    }
}