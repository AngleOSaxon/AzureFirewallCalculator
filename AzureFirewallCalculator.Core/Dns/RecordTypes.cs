namespace AzureFirewallCalculator.Core.Dns;

public record class GoogleDnsQuestion(string Name, DnsRequestType type);

public record class GoogleDnsAnswer(string Name, DnsRequestType Type, int TTL, string Data);

public record class GoogleDnsResponse(DnsResponseCode Status, bool TC, bool RD, bool RA, bool AD, bool CD, GoogleDnsQuestion[] Question, GoogleDnsAnswer[]? Answer, string? Comment);