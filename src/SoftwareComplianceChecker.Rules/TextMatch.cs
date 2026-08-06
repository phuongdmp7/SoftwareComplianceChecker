using System.Text;
using System.Text.RegularExpressions;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Case-insensitive text comparison helpers shared by the rule matcher.
/// </summary>
internal static class TextMatch
{
    /// <summary>
    /// Upper bound on a single regular expression evaluation.
    /// </summary>
    /// <remarks>
    /// Patterns come from a user-editable file, so a carelessly written rule can backtrack
    /// catastrophically. A timeout keeps one bad rule from hanging the whole scan.
    /// </remarks>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private const StringComparison Comparison = StringComparison.OrdinalIgnoreCase;

    /// <summary>Compares <paramref name="value"/> against <paramref name="pattern"/> using a literal match type.</summary>
    /// <param name="value">Text being tested.</param>
    /// <param name="pattern">Pattern to test against.</param>
    /// <param name="matchType">How to compare. <see cref="RuleMatchType.Regex"/> is handled by the caller.</param>
    public static bool Literal(string? value, string pattern, RuleMatchType matchType)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        return matchType switch
        {
            RuleMatchType.Contains => value.Contains(pattern, Comparison),
            RuleMatchType.StartsWith => value.StartsWith(pattern, Comparison),
            RuleMatchType.EndsWith => value.EndsWith(pattern, Comparison),
            RuleMatchType.Exact => value.Equals(pattern, Comparison),

            // Regex rules are pre-compiled; reaching here means the caller did not route them.
            RuleMatchType.Regex => false,
            _ => false,
        };
    }

    /// <summary>Whether <paramref name="value"/> contains <paramref name="fragment"/>, case-insensitively.</summary>
    /// <param name="value">Text being tested.</param>
    /// <param name="fragment">Fragment to look for.</param>
    public static bool ContainsFragment(string? value, string? fragment) =>
        !string.IsNullOrWhiteSpace(value)
        && !string.IsNullOrWhiteSpace(fragment)
        && value.Contains(fragment, Comparison);

    /// <summary>
    /// Builds a case-insensitive regular expression from a wildcard pattern using <c>*</c> and <c>?</c>.
    /// </summary>
    /// <param name="wildcard">Wildcard pattern, for example <c>Substance*.exe</c>.</param>
    public static Regex WildcardToRegex(string wildcard)
    {
        var builder = new StringBuilder("^");

        foreach (var c in wildcard)
        {
            builder.Append(c switch
            {
                '*' => ".*",
                '?' => ".",
                _ => Regex.Escape(c.ToString()),
            });
        }

        builder.Append('$');

        return new Regex(
            builder.ToString(),
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            RegexTimeout);
    }

    /// <summary>Compiles a user-supplied regular expression with the safety timeout applied.</summary>
    /// <param name="pattern">The pattern text.</param>
    public static Regex CompileUserRegex(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
}
