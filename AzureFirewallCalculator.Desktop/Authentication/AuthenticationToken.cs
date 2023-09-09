using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Identity.Client;

namespace AzureFirewallCalculator.Desktop.Authentication;

public class AuthenticationToken : TokenCredential
{
    public AuthenticationToken(IPublicClientApplication identityClient)
    {
        IdentityClient = identityClient;
    }

    public IPublicClientApplication IdentityClient { get; }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        var accounts = await IdentityClient.GetAccountsAsync();
        AuthenticationResult? result = null;
        try
        {
            result = await IdentityClient
                .AcquireTokenSilent(new [] { "https://management.azure.com/.default" }, accounts.FirstOrDefault())
                .ExecuteAsync();
        }
        catch (MsalUiRequiredException)
        {
            result = await IdentityClient
                .AcquireTokenInteractive(new [] { "https://management.azure.com/.default" })
                .ExecuteAsync();
        }
        catch (Exception ex)
        {
            // Display the error text - probably as a pop-up
            Debug.WriteLine($"Error: Authentication failed: {ex.Message}");
        }

        return new AccessToken(result!.AccessToken, result.ExpiresOn);
    }
}