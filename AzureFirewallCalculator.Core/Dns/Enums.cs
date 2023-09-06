namespace AzureFirewallCalculator.Core.Dns;

public enum DnsResponseCode
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    DomainDoesNotExist = 3,
    NotImplemented = 4,
    QueryRefused = 5,
    DomainShouldNotExistButDoes = 6,
    ResourceRecordSetShouldNotExistButDoes = 7,
    ServerNotAuthoritative = 8,
    NameNotInZone = 9
}

public enum DnsRequestType
{
    A = 1,
    AAAA = 28,
    CNAME = 5,
    TXT = 16
}