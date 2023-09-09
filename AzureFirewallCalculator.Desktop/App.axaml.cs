using System;
using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Desktop.Authentication;
using AzureFirewallCalculator.Desktop.FileImports;
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
        var desktop = ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
        Locator.CurrentMutable.RegisterViewsForViewModels(Assembly.GetCallingAssembly());
        Locator.CurrentMutable.Register(() => new LoadFromArmView(), typeof(IViewFor<LoadFromArmViewModel>));
        Locator.CurrentMutable.Register(() => new LoadFromFileView(), typeof(IViewFor<LoadFromFileViewModel>));
        Locator.CurrentMutable.Register(() => new CheckTrafficView(), typeof(IViewFor<CheckTrafficViewModel>));
        Locator.CurrentMutable.Register(() => new DefaultContentView(), typeof(IViewFor<DefaultContentViewModel>));
        Locator.CurrentMutable.RegisterLazySingleton(() => new AuthenticationService());
        if (desktop != null)
        {
            Locator.CurrentMutable.RegisterLazySingleton(() => new FileService(() => desktop.MainWindow!)); // TODO: less dumb way to resolve this cycle
        }
        Locator.CurrentMutable.RegisterLazySingleton<IDnsResolver>(() => new DynamicResolver());


        if (desktop != null)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(
                    authenticationService: Locator.Current.GetService<AuthenticationService>() ?? throw new ArgumentNullException(nameof(AuthenticationService)),
                    fileService: Locator.Current.GetService<FileService>() ?? throw new ArgumentNullException(nameof(FileService)),
                    dnsResolver: Locator.Current.GetService<IDnsResolver>() ?? throw new ArgumentNullException(nameof(IDnsResolver))
                )
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}