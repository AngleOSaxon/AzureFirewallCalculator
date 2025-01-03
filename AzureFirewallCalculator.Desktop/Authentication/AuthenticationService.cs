using System;
using System.Diagnostics;
using System.Linq;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Threading;
using Azure.Core;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Client.Extensions.Msal;
using Microsoft.IdentityModel.LoggingExtensions;

namespace AzureFirewallCalculator.Desktop.Authentication;

public class AuthenticationService
{
    public AuthenticationService(ILogger<AuthenticationService> logger, Config config, IApplicationLifetime applicationLifetime)
    {
        IdentityClient = PublicClientApplicationBuilder.Create("5fb5bdf1-9e6f-4a5a-a0cd-390f7fe43ec9") // TODO: Move this to config file
            .WithAuthority(AzureCloudInstance.AzurePublic, "common")
            .WithRedirectUri("http://localhost")
            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.Windows))
            .WithParentActivityOrWindow(() => Dispatcher.UIThread.Invoke(() => (applicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow?.TryGetPlatformHandle()?.Handle))
            // .WithLogging(new IdentityLoggerAdapter(logger))
            .Build();
        Logger = logger;
        Config = config;
    }

    private bool initialized = false;
    private IPublicClientApplication IdentityClient { get; }
    public ILogger<AuthenticationService> Logger { get; }
    public Config Config { get; }

    public AuthenticationToken GetAuthenticationToken() => new(this);
    public EventHandler<IAccount>? UserLogin;

    protected virtual void OnUserLogin(IAccount e)
    {
        UserLogin?.Invoke(this, e);
    }

    public async Task Init()
    {
        if (!initialized)
        {
            await AttachTokenCache();
            initialized = true;
        }
    }

    public async Task<AccessToken> GetAccessToken(CancellationToken cancellationToken)
    {
        var accounts = await IdentityClient.GetAccountsAsync();
        AuthenticationResult? result = null;
        try
        {
            result = await IdentityClient
                .AcquireTokenSilent(["https://management.azure.com/.default"], accounts.FirstOrDefault())
                .ExecuteAsync(cancellationToken);
        }
        catch (MsalUiRequiredException)
        {
            result = await IdentityClient
                .AcquireTokenInteractive(["https://management.azure.com/.default"])
                .WithSystemWebViewOptions(AuthenticationWebViewOptions.Options)
                .ExecuteAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Display the error text - probably as a pop-up
            Logger.LogError(ex, "Unable to log user in; error {exceptionMessage}", ex.Message);
        }

        if (result != null)
        {
            OnUserLogin(result.Account);
        }

        return new AccessToken(result!.AccessToken, result.ExpiresOn);
    }

    public async Task<IAccount?> GetCurrentIdentity()
    {
        return (await IdentityClient.GetAccountsAsync()).FirstOrDefault();
    }

    public async Task<bool> IsUserLoggedIn()
    {
        return (await GetCurrentIdentity()) != null;
    }

    private async Task AttachTokenCache()
    {
        var storageProperties = new StorageCreationPropertiesBuilder(Config.CacheFileName, Config.CacheFileDirectory)
            .WithLinuxKeyring(
                Config.LinuxKeyRingSchema,
                Config.LinuxKeyRingCollection,
                Config.LinuxKeyRingLabel,
                Config.LinuxKeyRingAttr1,
                Config.LinuxKeyRingAttr2
            )
            .WithMacKeyChain(
                Config.KeychainServiceName,
                Config.KeychainAccountName
            )
            .Build();
        var msalcachehelper = await MsalCacheHelper.CreateAsync(storageProperties);
        msalcachehelper.RegisterCache(IdentityClient.UserTokenCache);
    }
}