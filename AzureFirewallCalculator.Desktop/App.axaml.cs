using System;
using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using AzureFirewallCalculator.Core.ArmSource;
using AzureFirewallCalculator.Core.Dns;
using AzureFirewallCalculator.Desktop.Authentication;
using AzureFirewallCalculator.Desktop.FileImports;
using AzureFirewallCalculator.Desktop.Logging;
using AzureFirewallCalculator.Desktop.ViewModels;
using AzureFirewallCalculator.Desktop.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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

        var builder = Host.CreateApplicationBuilder();
        var loggingBuilder = builder.Logging;
        loggingBuilder.Services.AddSingleton<ILoggerProvider, InMemoryLoggerProvider>();
        loggingBuilder.AddConsole();
        loggingBuilder.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
        var loggerFactory = builder.Build().Services.CreateScope().ServiceProvider.GetRequiredService<ILoggerFactory>();
        Locator.CurrentMutable.Register(() => loggerFactory);

        Locator.CurrentMutable.RegisterViewsForViewModels(Assembly.GetCallingAssembly());
        Locator.CurrentMutable.Register(() => new LoadFromArmView(), typeof(IViewFor<LoadFromArmViewModel>));
        Locator.CurrentMutable.Register(() => new LoadFromFileView(), typeof(IViewFor<LoadFromFileViewModel>));
        Locator.CurrentMutable.Register(() => new CheckTrafficView(), typeof(IViewFor<CheckTrafficViewModel>));
        Locator.CurrentMutable.Register(() => new DefaultContentView(), typeof(IViewFor<DefaultContentViewModel>));
        Locator.CurrentMutable.RegisterLazySingleton(() => new AuthenticationService(loggerFactory.CreateLogger<AuthenticationService>()));
        Locator.CurrentMutable.RegisterLazySingleton(() => new ArmService(
            client: new Azure.ResourceManager.ArmClient(Locator.Current.GetService<AuthenticationService>()?.GetAuthenticationToken() ?? throw new ArgumentNullException(nameof(AuthenticationService))),
            dnsResolver:  Locator.Current.GetService<IDnsResolver>() ?? throw new ArgumentNullException(nameof(IDnsResolver)),
            logger: loggerFactory.CreateLogger<ArmService>())
        );
        if (desktop != null)
        {
            Locator.CurrentMutable.RegisterLazySingleton(() => new FileService(() => desktop.MainWindow!)); // TODO: less dumb way to resolve this cycle
        }
        Locator.CurrentMutable.RegisterLazySingleton<IDnsResolver>(() => new DynamicResolver(logger: loggerFactory.CreateLogger<DynamicResolver>()));
        Locator.CurrentMutable.RegisterLazySingleton(() => new InMemoryLogReader(InMemoryLogger.LogChannel.Reader, null));

        if (desktop != null)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(
                    authenticationService: Locator.Current.GetService<AuthenticationService>() ?? throw new ArgumentNullException(nameof(AuthenticationService)),
                    fileService: Locator.Current.GetService<FileService>() ?? throw new ArgumentNullException(nameof(FileService)),
                    dnsResolver: Locator.Current.GetService<IDnsResolver>() ?? throw new ArgumentNullException(nameof(IDnsResolver)),
                    inMemoryLogReader: Locator.Current.GetService<InMemoryLogReader>() ?? throw new ArgumentNullException(nameof(InMemoryLogReader)),
                    armService: Locator.Current.GetService<ArmService>() ?? throw new ArgumentNullException(nameof(ArmService)),
                    loggerFactory: loggerFactory
                )
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}