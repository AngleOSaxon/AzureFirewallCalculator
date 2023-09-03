using System.Data;
using System.Net;

namespace AzureFirewallCalculator.Core;

public readonly record struct NetworkRequest
{
    public uint SourceIp { get; }

    public uint DestinationIp { get; }

    public ushort DestinationPort { get; }

    public NetworkProtocols Protocol { get; }

    public NetworkRequest(uint sourceIp, uint destinationIp, ushort destinationPort, NetworkProtocols protocol)
    {
        SourceIp = sourceIp;
        DestinationIp = destinationIp;
        DestinationPort = destinationPort;
        Protocol  = protocol;
    }

    public NetworkRequest(IPAddress sourceIp, IPAddress destinationIp, ushort destinationPort, NetworkProtocols protocol)
        : this(sourceIp.ConvertToUint(), destinationIp.ConvertToUint(), destinationPort, protocol) { }

    public NetworkRequest(string sourceIp, string destinationIp, ushort destinationPort, NetworkProtocols protocol)
        : this(IPAddress.Parse(sourceIp), IPAddress.Parse(destinationIp), destinationPort, protocol) { }


    public void Deconstruct(out uint sourceIp, out uint destinationIp, out ushort destinationPort, out NetworkProtocols protocol)
    {
        sourceIp = SourceIp;
        destinationIp = DestinationIp;
        destinationPort = DestinationPort;
        protocol = Protocol;
    }
}