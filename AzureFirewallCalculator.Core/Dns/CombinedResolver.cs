using Microsoft.Extensions.Logging;

namespace AzureFirewallCalculator.Core.Dns;

public class CombinedResolver : IDnsResolver
{
    public IDnsResolver[] Resolvers { get; set; }
    public ILogger<CombinedResolver> Logger { get; }

    public CombinedResolver(ILogger<CombinedResolver> logger, params IDnsResolver[] resolvers)
    {
        Resolvers = resolvers;
        Logger = logger;
    }

    public async Task<uint[]> ResolveAddress(string fqdn)
    {
        var tasks = Resolvers.Select(async item => 
        {
            // Wrap in try/catch to ensure loose exceptions can't kill us
            try
            {
                return await item.ResolveAddress(fqdn);
            }
            catch (Exception ex)
            {
                Logger.LogWarning(ex, "{exceptionMessage}", ex.Message);
                return [];
            }
        });
        foreach (var task in tasks)
        {
            var result = await task;
            if (result.Length > 0)
            {
                return result;
            }
        }

        return [];
    }
}