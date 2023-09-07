using Azure.Core;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

namespace AzureFirewallCalculator.BlazorWasm.Utils;

public class AccessProviderTokenCredential : TokenCredential
{
    public AccessProviderTokenCredential(IAccessTokenProvider provider)
    {
        Provider = provider;
    }

    public IAccessTokenProvider Provider { get; }

    public override Azure.Core.AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public override async ValueTask<Azure.Core.AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        var token = await Provider.RequestAccessToken(new AccessTokenRequestOptions
        {
            Scopes = requestContext.Scopes
        });
        // TODO: Log result
        token.TryGetToken(out var realToken);
        return new Azure.Core.AccessToken(realToken.Value, realToken.Expires);
    }
}