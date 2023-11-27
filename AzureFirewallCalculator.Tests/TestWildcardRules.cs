using System.Reflection.Metadata.Ecma335;
using AzureFirewallCalculator.Core;

namespace AzureFirewallCalculator.Tests;

public class TestWildcardRules
{

    public static IEnumerable<object[]> SourceData()
    {
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            false
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.bar.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com.foo", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            false
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "*example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 443) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            true
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "foo.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 8080) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443)),
            false
        };
        yield return new object[] 
        {
            new ApplicationRule("", new RuleIpRange[] { new(uint.MinValue, uint.MinValue) }, new string[] { "foo.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new(ApplicationProtocol.Https, 8080) }),
            new ApplicationRequest(uint.MinValue, "foo.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, null)),
            true
        };
    }

    [Theory]
    [MemberData(nameof(SourceData))]
    public void TestApplicationWildcardRules(ApplicationRule rule, ApplicationRequest request, bool shouldBeAllowed)
    {
        Assert.Equal(expected: shouldBeAllowed, actual: rule.Matches(request).Matched);
    }

    [Fact]
    public void TestUnboundedWildcard()
    {
        var rule = new ApplicationRule("", new RuleIpRange[] { new (uint.MinValue, uint.MaxValue) }, new string[] { "*", "bar.com", "*.example.com" }, Array.Empty<string>(), new ApplicationProtocolPort[] { new (ApplicationProtocol.Https, 443) } );
        var request1 = new ApplicationRequest(uint.MinValue, "unmatched.bar.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));

        var request1Match = rule.Matches(request1);
        Assert.Single(request1Match.MatchedTargetFqdns);
        Assert.Contains("*", request1Match.MatchedTargetFqdns);
        
        var request2 = new ApplicationRequest(uint.MinValue, "bar.example.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));
        var request2Match = rule.Matches(request2);
        Assert.Equal(2, request2Match.MatchedTargetFqdns.Length);
        Assert.Contains("*.example.com", request2Match.MatchedTargetFqdns);
        Assert.Contains("*", request2Match.MatchedTargetFqdns);

        var request3 = new ApplicationRequest(uint.MinValue, "bar.com", new ApplicationProtocolPort(ApplicationProtocol.Https, 443));
        var request3Match = rule.Matches(request3);
        Assert.Equal(2, request3Match.MatchedTargetFqdns.Length);
        Assert.Contains("bar.com", request3Match.MatchedTargetFqdns);
        Assert.Contains("*", request3Match.MatchedTargetFqdns);
    }
}