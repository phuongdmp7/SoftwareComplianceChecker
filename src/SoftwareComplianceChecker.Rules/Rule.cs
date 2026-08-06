using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// How a rule's text patterns are compared against a software name.
/// </summary>
public enum RuleMatchType
{
    /// <summary>The name contains the pattern.</summary>
    Contains = 0,

    /// <summary>The name begins with the pattern.</summary>
    StartsWith = 1,

    /// <summary>The name ends with the pattern.</summary>
    EndsWith = 2,

    /// <summary>The name matches the pattern as a regular expression.</summary>
    Regex = 3,

    /// <summary>The name equals the pattern exactly.</summary>
    Exact = 4,
}

/// <summary>
/// One compliance policy rule, loaded from rules.json.
/// </summary>
/// <remarks>
/// <para>
/// A rule matches when <em>any</em> of its configured criteria match. This is what lets a
/// single rule express "everything published by Adobe" alongside named products.
/// </para>
/// <para>
/// All comparison is case-insensitive.
/// </para>
/// </remarks>
public sealed class Rule
{
    /// <summary>Descriptive name, surfaced in reports so a verdict can be traced to its rule.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Policy category, for example <c>Adobe</c>, used for grouping and filtering.</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>How <see cref="Aliases"/> are compared against the software name.</summary>
    public RuleMatchType MatchType { get; set; } = RuleMatchType.Contains;

    /// <summary>Name patterns to compare against the software display name.</summary>
    public List<string> Aliases { get; set; } = [];

    /// <summary>Publisher substring to compare against the software publisher.</summary>
    public string? Publisher { get; set; }

    /// <summary>
    /// Executable file names to compare against portable software.
    /// Supports <c>*</c> and <c>?</c> wildcards, for example <c>Substance*.exe</c>.
    /// </summary>
    public List<string> ExecutableNames { get; set; } = [];

    /// <summary>Folder name fragments to compare against the software location.</summary>
    public List<string> FolderNames { get; set; } = [];

    /// <summary>
    /// Resolution order. The highest priority among matching rules wins.
    /// </summary>
    public int Priority { get; set; }

    /// <summary>Verdict applied when this rule matches.</summary>
    public ComplianceStatus Status { get; set; } = ComplianceStatus.Fail;

    /// <summary>Justification recorded against the verdict.</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>Whether this rule participates in evaluation.</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// The complete compliance policy, as loaded from rules.json.
/// </summary>
public sealed class RuleSet
{
    /// <summary>Schema version of the rules file.</summary>
    public int Version { get; set; } = 1;

    /// <summary>Free-text description of the policy.</summary>
    public string? Description { get; set; }

    /// <summary>The rules, in file order.</summary>
    public List<Rule> Rules { get; set; } = [];
}
