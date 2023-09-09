using System;
using System.Diagnostics;
using System.Linq;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Identity.Client;

namespace AzureFirewallCalculator.Desktop.Authentication;

public class AuthenticationService
{
    public AuthenticationService()
    {
        IdentityClient = PublicClientApplicationBuilder.Create("5fb5bdf1-9e6f-4a5a-a0cd-390f7fe43ec9")
            .WithAuthority(AzureCloudInstance.AzurePublic, "common")
            .WithRedirectUri("http://localhost")
            .Build();
    }

    private IPublicClientApplication IdentityClient { get; }
    public AuthenticationToken GetAuthenticationToken() => new(this);
    public EventHandler<IAccount>? UserLogin;

    protected virtual void OnUserLogin(IAccount e)
    {
        UserLogin?.Invoke(this, e);
    }

    public async Task<AccessToken> GetAccessToken(CancellationToken cancellationToken)
    {
        var accounts = await IdentityClient.GetAccountsAsync();
        AuthenticationResult? result = null;
        try
        {
            result = await IdentityClient
                .AcquireTokenSilent(new [] { "https://management.azure.com/.default" }, accounts.FirstOrDefault())
                .ExecuteAsync(cancellationToken);
        }
        catch (MsalUiRequiredException)
        {
            result = await IdentityClient
                .AcquireTokenInteractive(new [] { "https://management.azure.com/.default" })
                .ExecuteAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Display the error text - probably as a pop-up
            Debug.WriteLine($"Error: Authentication failed: {ex.Message}");
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
}