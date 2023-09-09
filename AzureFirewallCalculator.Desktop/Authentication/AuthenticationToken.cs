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
    public AuthenticationToken(AuthenticationService identityClient)
    {
        AuthenticationService = identityClient;
    }

    public AuthenticationService AuthenticationService { get; }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return await AuthenticationService.GetAccessToken(cancellationToken);
    }
}