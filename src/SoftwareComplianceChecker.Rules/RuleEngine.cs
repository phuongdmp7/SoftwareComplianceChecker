using System.Collections.Concurrent;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Evaluates software against the loaded policy.
/// </summary>
/// <remarks>
/// <para>
/// Rules are considered in descending <see cref="Rule.Priority"/> order and the first match
/// wins, so a specific rule can override a broad one without editing the broad rule.
/// </para>
/// <para>
/// Software matching no rule passes. The policy is default-allow by design: an unknown tool
/// is not evidence of a violation.
/// </para>
/// </remarks>
public sealed class RuleEngine : IRuleEngine
{
    private const string NoMatchReason = "No matching compliance rule.";

    private readonly IReadOnlyList<CompiledRule> compiledRules;
    private readonly ConcurrentQueue<string> diagnostics = new();

    /// <summary>Creates an engine over a validated rule set.</summary>
    /// <param name="ruleSet">The policy to apply.</param>
    /// <exception cref="RuleConfigurationException">The rule set is not valid.</exception>
    public RuleEngine(RuleSet ruleSet)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);

        var errors = RuleSetValidator.Validate(ruleSet);
        if (errors.Count > 0)
        {
            throw new RuleConfigurationException("The compliance policy is not valid.", errors);
        }

        this.compiledRules = ruleSet.Rules
            .Where(r => r.Enabled)
            .OrderByDescending(r => r.Priority)
            .Select(r => new CompiledRule(r))
            .ToArray();
    }

    /// <summary>Number of enabled rules in effect.</summary>
    public int RuleCount => this.compiledRules.Count;

    /// <summary>
    /// Problems encountered while evaluating, such as a pattern that timed out.
    /// </summary>
    /// <remarks>
    /// Surfaced into the report's warnings rather than swallowed, so a rule that never
    /// evaluates cannot masquerade as a rule that never matched.
    /// </remarks>
    public IReadOnlyList<string> Diagnostics => this.diagnostics.Distinct().ToArray();

    /// <inheritdoc />
    public RuleVerdict Evaluate(SoftwareItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        foreach (var compiled in this.compiledRules)
        {
            if (!compiled.Matches(item, this.diagnostics.Enqueue))
            {
                continue;
            }

            var rule = compiled.Rule;

            return new RuleVerdict(
                rule.Status,
                rule.Reason,
                string.IsNullOrWhiteSpace(rule.Category) ? null : rule.Category,
                string.IsNullOrWhiteSpace(rule.Name) ? null : rule.Name);
        }

        return new RuleVerdict(ComplianceStatus.Pass, NoMatchReason);
    }
}
