using System.Text.RegularExpressions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// A <see cref="Rule"/> with its regular expressions compiled once, ready for repeated evaluation.
/// </summary>
internal sealed class CompiledRule
{
    private readonly Regex[] aliasRegexes;
    private readonly Regex[] executableRegexes;

    /// <summary>Compiles a rule for evaluation.</summary>
    /// <param name="rule">The rule to compile.</param>
    /// <exception cref="ArgumentException">A regular expression in the rule is not valid.</exception>
    public CompiledRule(Rule rule)
    {
        this.Rule = rule;

        this.aliasRegexes = rule.MatchType == RuleMatchType.Regex
            ? rule.Aliases.Where(a => !string.IsNullOrWhiteSpace(a))
                          .Select(TextMatch.CompileUserRegex)
                          .ToArray()
            : [];

        // Executable names always support wildcards regardless of the rule's match type,
        // because file-name patterns such as "Substance*.exe" are the natural way to write them.
        this.executableRegexes = rule.ExecutableNames
            .Where(e => !string.IsNullOrWhiteSpace(e))
            .Select(TextMatch.WildcardToRegex)
            .ToArray();
    }

    /// <summary>The underlying rule.</summary>
    public Rule Rule { get; }

    /// <summary>
    /// Whether this rule matches an item. A rule matches when any configured criterion matches.
    /// </summary>
    /// <param name="item">The item to test.</param>
    /// <param name="onDiagnostic">Receives a message when a pattern could not be evaluated.</param>
    public bool Matches(SoftwareItem item, Action<string>? onDiagnostic = null)
    {
        return this.MatchesName(item, onDiagnostic)
               || this.MatchesPublisher(item)
               || this.MatchesExecutable(item, onDiagnostic)
               || this.MatchesFolder(item);
    }

    private bool MatchesName(SoftwareItem item, Action<string>? onDiagnostic)
    {
        if (this.Rule.MatchType == RuleMatchType.Regex)
        {
            foreach (var regex in this.aliasRegexes)
            {
                if (SafeIsMatch(regex, item.DisplayName, this.Rule.Name, onDiagnostic))
                {
                    return true;
                }
            }

            return false;
        }

        return this.Rule.Aliases.Any(alias =>
            TextMatch.Literal(item.DisplayName, alias, this.Rule.MatchType));
    }

    private bool MatchesPublisher(SoftwareItem item) =>
        TextMatch.ContainsFragment(item.Publisher, this.Rule.Publisher);

    private bool MatchesExecutable(SoftwareItem item, Action<string>? onDiagnostic)
    {
        if (this.executableRegexes.Length == 0)
        {
            return false;
        }

        var candidates = new[] { item.ExecutableName, TryGetFileName(item.SourcePath) };

        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            foreach (var regex in this.executableRegexes)
            {
                if (SafeIsMatch(regex, candidate, this.Rule.Name, onDiagnostic))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool MatchesFolder(SoftwareItem item) =>
        this.Rule.FolderNames.Any(folder => TextMatch.ContainsFragment(item.Location, folder));

    private static string? TryGetFileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFileName(path);
        }
        catch (ArgumentException)
        {
            // A path containing invalid characters is not a usable file name.
            return null;
        }
    }

    /// <summary>
    /// Evaluates a regular expression, converting a timeout into a reported diagnostic rather
    /// than an exception that would abort the scan.
    /// </summary>
    private static bool SafeIsMatch(Regex regex, string input, string ruleName, Action<string>? onDiagnostic)
    {
        try
        {
            return regex.IsMatch(input);
        }
        catch (RegexMatchTimeoutException)
        {
            onDiagnostic?.Invoke(
                $"Rule '{ruleName}' has a pattern that timed out evaluating '{input}' and was skipped. " +
                "Simplify the regular expression in rules.json.");

            return false;
        }
    }
}
