namespace AzureFirewallCalculator.Tests;

public static class Util
{
    public static bool ElementByElementCompare<T>(this IEnumerable<T> source, IEnumerable<T> comparison)
    {
        return source.ElementByElementCompare(comparison, (s, c) => s?.Equals(c) ?? false);
    }

    public static bool ElementByElementCompare<T>(this IEnumerable<T> source, IEnumerable<T> comparison, Func<T, T, bool> comparator)
    {
        if (source.Count() != comparison.Count())
        {
            throw new ArgumentException("Length of 'source' did not match length of 'comparison'");
        }
        for (int i = 0; i < source.Count(); i++)
        {
            var result = comparator(source.ElementAt(i), comparison.ElementAt(i));
            if (!result)
            {
                return false;
            }
        }
        return true;
    }
}