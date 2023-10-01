using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using AzureFirewallCalculator.BlazorWasm;
using AzureFirewallCalculator.Core.Dns;
using System.Net.Http;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using AzureFirewallCalculator.BlazorWasm.Utils;
using AzureFirewallCalculator.Core.ArmSource;
using Azure.Core;
using Azure.ResourceManager;


var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddHttpClient<GoogleDnsResolver>();
builder.Services.AddScoped<GoogleDnsResolver>();
builder.Services.AddScoped<CombinedResolver>();
builder.Services.AddScoped<IDnsResolver>(sp => new CombinedResolver(sp.GetRequiredService<ILogger<CombinedResolver>>(), sp.GetRequiredService<GoogleDnsResolver>()));

builder.Services.AddScoped<TokenCredential, AccessProviderTokenCredential>();
builder.Services.AddScoped<ArmClient>();
builder.Services.AddScoped<ArmService>();

builder.Services.AddMsalAuthentication(options =>
{
    options.ProviderOptions.Authentication.ClientId = "5fb5bdf1-9e6f-4a5a-a0cd-390f7fe43ec9";
    options.ProviderOptions.Authentication.Authority = "https://login.microsoftonline.com/common/";
    options.ProviderOptions.LoginMode = "Redirect";
    options.ProviderOptions.DefaultAccessTokenScopes.Add("https://management.azure.com/.default");
});

await builder.Build().RunAsync();
