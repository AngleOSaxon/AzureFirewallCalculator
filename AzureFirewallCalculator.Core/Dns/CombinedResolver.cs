namespace AzureFirewallCalculator.Core.Dns;

public class CombinedResolver : IDnsResolver
{
    public IDnsResolver[] Resolvers { get; set; }

    public CombinedResolver(params IDnsResolver[] resolvers)
    {
        Resolvers = resolvers;
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
            catch
            {
                // TODO: Logging
                return Array.Empty<uint>();
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

        return Array.Empty<uint>();
    }
}