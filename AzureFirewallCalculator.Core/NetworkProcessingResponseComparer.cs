using System.Diagnostics.CodeAnalysis;
using Azure.ResourceManager.Network.Models;

namespace AzureFirewallCalculator.Core;

public class NetworkProcessingResponseComparer : IEqualityComparer<NetworkProcessingResponse>
{
    public bool Equals(NetworkProcessingResponse? x, NetworkProcessingResponse? y)
    {
        if (x?.MatchedRules.Length != y?.MatchedRules.Length)
        {
            return false;
        }
        if (x?.CollectionName != y?.CollectionName)
        {
            return false;
        }
        
        var matches = x?.MatchedRules.IntersectBy(y?.MatchedRules?.Select(item => item.Rule.Name) ?? [], item => item.Rule.Name);
        if (matches == null)
        {
            return false;
        }
        return matches.Any();
    }

    public int GetHashCode([DisallowNull] NetworkProcessingResponse obj)
    {
        return (obj.CollectionName.GetHashCode() ^ obj.MatchedRules.Length) * 37;
    }
}