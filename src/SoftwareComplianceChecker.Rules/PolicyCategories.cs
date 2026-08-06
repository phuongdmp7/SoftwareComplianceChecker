namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Category names the application gives special meaning to.
/// </summary>
/// <remarks>
/// Categories are otherwise free text used only for grouping. The one exception is
/// <see cref="ActivationTool"/>: the Windows license scanner reads the patterns from rules
/// in that category so its detection list stays policy data rather than compiled-in strings.
/// </remarks>
public static class PolicyCategories
{
    /// <summary>Rules describing Windows activation tools.</summary>
    public const string ActivationTool = "Activation Tool";
}

/// <summary>
/// Supplies activation tool name patterns to the Windows license scanner.
/// </summary>
public interface IActivationToolPatternSource
{
    /// <summary>Returns the tool names and executable patterns to search for.</summary>
    IReadOnlyList<string> GetPatterns();
}

/// <summary>
/// Draws activation tool patterns from the loaded compliance policy.
/// </summary>
public sealed class RuleSetActivationToolPatternSource : IActivationToolPatternSource
{
    private readonly IReadOnlyList<string> patterns;

    /// <summary>Extracts the patterns from a rule set.</summary>
    /// <param name="ruleSet">The loaded policy.</param>
    public RuleSetActivationToolPatternSource(RuleSet ruleSet)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);

        this.patterns = ruleSet.Rules
            .Where(r => r.Enabled
                        && string.Equals(r.Category, PolicyCategories.ActivationTool, StringComparison.OrdinalIgnoreCase))
            .SelectMany(r => r.Aliases.Concat(r.ExecutableNames))
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetPatterns() => this.patterns;
}
