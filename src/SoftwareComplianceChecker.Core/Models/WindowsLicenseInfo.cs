namespace SoftwareComplianceChecker.Core.Models;

/// <summary>
/// How a Windows installation was activated.
/// </summary>
public enum ActivationType
{
    /// <summary>Could not be determined from the available evidence.</summary>
    Unknown = 0,

    /// <summary>Retail channel.</summary>
    Retail = 1,

    /// <summary>Pre-installed by a hardware manufacturer.</summary>
    Oem = 2,

    /// <summary>OEM digital marker, keyed to the firmware.</summary>
    OemDm = 3,

    /// <summary>OEM certificate of authenticity.</summary>
    OemCoa = 4,

    /// <summary>Multiple activation key.</summary>
    Mak = 5,

    /// <summary>Volume licensing, channel not further resolved.</summary>
    Volume = 6,

    /// <summary>Key Management Service activation.</summary>
    Kms = 7,
}

/// <summary>
/// Raw, unjudged facts collected about the Windows license.
/// </summary>
/// <remarks>
/// Separated from the verdict so that <see cref="ComplianceStatus"/> is derived by a pure
/// function that can be unit tested without touching WMI or the registry.
/// </remarks>
public sealed record LicenseEvidence
{
    /// <summary>Windows edition, for example Pro or Home.</summary>
    public string? Edition { get; init; }

    /// <summary>Full product name reported by the operating system.</summary>
    public string? ProductName { get; init; }

    /// <summary>Windows version, for example 23H2.</summary>
    public string? Version { get; init; }

    /// <summary>Operating system build number.</summary>
    public string? BuildNumber { get; init; }

    /// <summary>Licensing status text, for example Licensed or Notification.</summary>
    public string? LicenseStatus { get; init; }

    /// <summary>Raw numeric licensing status reported by Windows.</summary>
    public int? LicenseStatusCode { get; init; }

    /// <summary>Product key channel reported by Windows, for example Retail, OEM or Volume:MAK.</summary>
    public string? ProductKeyChannel { get; init; }

    /// <summary>Description of the installed license.</summary>
    public string? LicenseDescription { get; init; }

    /// <summary>Last five characters of the product key.</summary>
    public string? PartialProductKey { get; init; }

    /// <summary>Whether an OEM product key is present in firmware.</summary>
    public bool OemBiosKeyPresent { get; init; }

    /// <summary>Configured KMS host name, when one is set.</summary>
    public string? KmsServerName { get; init; }

    /// <summary>Configured KMS host port, when one is set.</summary>
    public int? KmsServerPort { get; init; }

    /// <summary>Remaining activation period in minutes, when reported.</summary>
    public int? GracePeriodMinutes { get; init; }

    /// <summary>Activation tools found on the machine, described for the report.</summary>
    public IReadOnlyList<string> ActivationToolTraces { get; init; } = [];

    /// <summary>Surfaces that could not be read, for example because elevation was required.</summary>
    public IReadOnlyList<string> InaccessibleSources { get; init; } = [];
}

/// <summary>
/// The evaluated Windows licensing result: the collected evidence plus the verdict drawn from it.
/// </summary>
public sealed record WindowsLicenseInfo
{
    /// <summary>The facts the verdict was drawn from.</summary>
    public required LicenseEvidence Evidence { get; init; }

    /// <summary>Activation type inferred from the evidence.</summary>
    public required ActivationType ActivationType { get; init; }

    /// <summary>Individual observations that indicate KMS activation. Empty when none were found.</summary>
    public required IReadOnlyList<string> KmsEvidence { get; init; }

    /// <summary>Verdict for the Windows license.</summary>
    public required ComplianceStatus Status { get; init; }

    /// <summary>Human-readable justification for <see cref="Status"/>.</summary>
    public required string Reason { get; init; }

    /// <summary>Whether any evidence of KMS activation was found.</summary>
    public bool HasKmsEvidence => this.KmsEvidence.Count > 0;
}
