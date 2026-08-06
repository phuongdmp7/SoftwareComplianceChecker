using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Core.Abstractions;

/// <summary>
/// The verdict the policy produced for a single software item.
/// </summary>
/// <param name="Status">Whether the item passes or fails.</param>
/// <param name="Reason">Human-readable justification.</param>
/// <param name="Category">Policy category of the matching rule, if any.</param>
/// <param name="RuleName">Name of the matching rule, if any.</param>
public sealed record RuleVerdict(
    ComplianceStatus Status,
    string Reason,
    string? Category = null,
    string? RuleName = null);

/// <summary>
/// Applies the compliance policy to discovered software.
/// </summary>
/// <remarks>
/// Scanners never decide compliance; they discover. This is the only component that
/// assigns a <see cref="ComplianceStatus"/> to software.
/// </remarks>
public interface IRuleEngine
{
    /// <summary>
    /// Evaluates a single item against the policy.
    /// </summary>
    /// <param name="item">The discovered software.</param>
    /// <returns>
    /// The verdict. Items matching no rule pass: the policy is default-allow.
    /// </returns>
    RuleVerdict Evaluate(SoftwareItem item);
}
