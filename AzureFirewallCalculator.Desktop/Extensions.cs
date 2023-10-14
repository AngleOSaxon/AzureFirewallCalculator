using System;
using Splat;

namespace AzureFirewallCalculator.Desktop;

public static class Extensions
{
    public static TService GetRequiredService<TService>(this IReadonlyDependencyResolver locator) => locator.GetService<TService>() ?? throw new InvalidOperationException($"No registered service for type '{typeof(TService).Name}'");
}