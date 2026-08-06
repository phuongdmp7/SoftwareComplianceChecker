using System.Text.RegularExpressions;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Checks that a loaded rule set is usable before any scan relies on it.
/// </summary>
public static class RuleSetValidator
{
    /// <summary>
    /// Validates a rule set and returns every problem found.
    /// </summary>
    /// <param name="ruleSet">The rule set to check.</param>
    /// <returns>An empty list when the rule set is valid.</returns>
    /// <remarks>
    /// All problems are collected rather than stopping at the first, so a user fixing
    /// rules.json sees the whole list in one pass.
    /// </remarks>
    public static IReadOnlyList<string> Validate(RuleSet ruleSet)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);

        var errors = new List<string>();

        if (ruleSet.Version <= 0)
        {
            errors.Add($"Version must be a positive number but was {ruleSet.Version}.");
        }

        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < ruleSet.Rules.Count; i++)
        {
            var rule = ruleSet.Rules[i];
            var label = string.IsNullOrWhiteSpace(rule.Name) ? $"rule at index {i}" : $"rule '{rule.Name}'";

            if (string.IsNullOrWhiteSpace(rule.Name))
            {
                errors.Add($"The {label} has no name. Every rule needs a name so verdicts can be traced back to it.");
            }
            else if (!seenNames.Add(rule.Name))
            {
                errors.Add($"Duplicate rule name '{rule.Name}'. Rule names must be unique.");
            }

            if (string.IsNullOrWhiteSpace(rule.Reason))
            {
                errors.Add($"The {label} has no reason. Every verdict must be explainable.");
            }

            if (!HasAnyCriterion(rule))
            {
                errors.Add(
                    $"The {label} defines no criteria. Set at least one of aliases, publisher, " +
                    "executableNames or folderNames, otherwise the rule can never match.");
            }

            if (rule.MatchType == RuleMatchType.Regex)
            {
                errors.AddRange(ValidateRegexes(rule, label));
            }

            errors.AddRange(ValidateWildcards(rule, label));
        }

        return errors;
    }

    private static bool HasAnyCriterion(Rule rule) =>
        rule.Aliases.Any(a => !string.IsNullOrWhiteSpace(a))
        || !string.IsNullOrWhiteSpace(rule.Publisher)
        || rule.ExecutableNames.Any(e => !string.IsNullOrWhiteSpace(e))
        || rule.FolderNames.Any(f => !string.IsNullOrWhiteSpace(f));

    private static IEnumerable<string> ValidateRegexes(Rule rule, string label)
    {
        foreach (var alias in rule.Aliases.Where(a => !string.IsNullOrWhiteSpace(a)))
        {
            var error = TryCompile(() => TextMatch.CompileUserRegex(alias));
            if (error is not null)
            {
                yield return $"The {label} has an invalid regular expression '{alias}': {error}";
            }
        }
    }

    private static IEnumerable<string> ValidateWildcards(Rule rule, string label)
    {
        foreach (var executable in rule.ExecutableNames.Where(e => !string.IsNullOrWhiteSpace(e)))
        {
            var error = TryCompile(() => TextMatch.WildcardToRegex(executable));
            if (error is not null)
            {
                yield return $"The {label} has an executable pattern '{executable}' that cannot be compiled: {error}";
            }
        }
    }

    private static string? TryCompile(Func<Regex> compile)
    {
        try
        {
            _ = compile();
            return null;
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }
}
