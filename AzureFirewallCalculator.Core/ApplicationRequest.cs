using System.Data;
using System.Net;

namespace AzureFirewallCalculator.Core;

public readonly record struct ApplicationRequest
{
    public uint SourceIp { get; }

    public string DestinationFqdn { get; }

    public ApplicationProtocolPort Protocol { get; }

    public ApplicationRequest(uint sourceIp, string destinationFqdn, ApplicationProtocolPort protocol)
    {
        SourceIp = sourceIp;
        DestinationFqdn = destinationFqdn.ToLower();
        Protocol  = protocol;
    }

    public ApplicationRequest(IPAddress sourceIp, string destinationIp, ApplicationProtocolPort protocol)
        : this(sourceIp.ConvertToUint(), destinationIp, protocol) { }

    public ApplicationRequest(string sourceIp, string destinationFqdn, ApplicationProtocolPort protocol)
        : this(IPAddress.Parse(sourceIp), destinationFqdn, protocol) { }


    public void Deconstruct(out uint sourceIp, out string destinationFqdn, out ApplicationProtocolPort protocol)
    {
        sourceIp = SourceIp;
        destinationFqdn = DestinationFqdn;
        protocol = Protocol;
    }
}