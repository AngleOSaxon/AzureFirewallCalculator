using System;
using System.Reflection;
using System.Threading.Tasks;
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

        Locator.CurrentMutable.RegisterViewsForViewModels(Assembly.GetExecutingAssembly());
        Locator.CurrentMutable.RegisterLazySingleton(() => new AuthenticationService(loggerFactory.CreateLogger<AuthenticationService>()));
        Locator.CurrentMutable.RegisterLazySingleton(() => new StaticDnsResolver());
        Locator.CurrentMutable.RegisterLazySingleton(() => new ArmService(
            client: new Azure.ResourceManager.ArmClient(Locator.Current.GetRequiredService<AuthenticationService>().GetAuthenticationToken()),
            dnsResolver:  Locator.Current.GetRequiredService<IDnsResolver>(),
            logger: loggerFactory.CreateLogger<ArmService>())
        );
        if (desktop != null)
        {
            Locator.CurrentMutable.RegisterLazySingleton(() => new FileService(() => desktop.MainWindow!)); // TODO: less dumb way to resolve this cycle
        }
        Locator.CurrentMutable.RegisterLazySingleton(() => new DynamicResolver(logger: loggerFactory.CreateLogger<DynamicResolver>()));
        Locator.CurrentMutable.RegisterLazySingleton<IDnsResolver>(() => new CombinedResolver(
            logger: loggerFactory.CreateLogger<CombinedResolver>(),
            Locator.Current.GetRequiredService<StaticDnsResolver>(),
            Locator.Current.GetRequiredService<DynamicResolver>()
        ));
        Locator.CurrentMutable.RegisterLazySingleton(() => new InMemoryLogReader(InMemoryLogger.LogChannel.Reader, null));

        var unhandledFailureLogger = loggerFactory.CreateLogger("UnhandledTaskException");
        TaskScheduler.UnobservedTaskException += (object? sender, UnobservedTaskExceptionEventArgs e) =>
        {
            if (e.Exception is AggregateException aggregateException)
            {
                foreach (var exception in aggregateException.InnerExceptions)
                {
                    unhandledFailureLogger.LogError(exception, "Unexpected error: {errorMessage}", exception);
                }
            }
            else
            {
                unhandledFailureLogger.LogError(e.Exception, "Unexpected error: {errorMessage}", e.Exception.ToString());
            }
        };

        if (desktop != null)
        {
            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(
                    authenticationService: Locator.Current.GetRequiredService<AuthenticationService>(),
                    fileService: Locator.Current.GetRequiredService<FileService>(),
                    dnsResolver: Locator.Current.GetRequiredService<IDnsResolver>(),
                    inMemoryLogReader: Locator.Current.GetRequiredService<InMemoryLogReader>(),
                    armService: Locator.Current.GetRequiredService<ArmService>(),
                    loggerFactory: loggerFactory
                )
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}