using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using AzureFirewallCalculator.BlazorWasm;
using AzureFirewallCalculator.Core.Dns;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddHttpClient<GoogleDnsResolver>();
builder.Services.AddScoped<IDnsResolver>(sp => new CombinedResolver(new GoogleDnsResolver(sp.GetRequiredService<HttpClient>())));

await builder.Build().RunAsync();
