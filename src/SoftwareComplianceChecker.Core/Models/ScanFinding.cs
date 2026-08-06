namespace SoftwareComplianceChecker.Core.Models;

/// <summary>
/// A software item that has been evaluated against the compliance policy.
/// </summary>
public sealed record ScanFinding
{
    /// <summary>Name of the evaluated item.</summary>
    public required string Name { get; init; }

    /// <summary>Publisher, when known.</summary>
    public string? Publisher { get; init; }

    /// <summary>Version, when known.</summary>
    public string? Version { get; init; }

    /// <summary>Install directory or file path.</summary>
    public string? Location { get; init; }

    /// <summary>Verdict for this item.</summary>
    public required ComplianceStatus Status { get; init; }

    /// <summary>Human-readable justification for <see cref="Status"/>.</summary>
    public required string Reason { get; init; }

    /// <summary>Policy category the matching rule belongs to, when a rule matched.</summary>
    public string? Category { get; init; }

    /// <summary>Name of the rule that produced this verdict, when a rule matched.</summary>
    public string? MatchedRule { get; init; }

    /// <summary>Which report section this finding belongs to.</summary>
    public required FindingSection Section { get; init; }
}

/// <summary>
/// The report section a <see cref="ScanFinding"/> belongs to.
/// </summary>
public enum FindingSection
{
    /// <summary>Windows licensing and activation.</summary>
    WindowsLicense = 0,

    /// <summary>Software registered as installed.</summary>
    InstalledSoftware = 1,

    /// <summary>Software found on disk without installation.</summary>
    PortableSoftware = 2,
}
