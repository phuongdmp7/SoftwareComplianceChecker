namespace SoftwareComplianceChecker.Core.Models;

/// <summary>
/// The complete result of a compliance scan.
/// </summary>
public sealed record ComplianceReport
{
    /// <summary>Name of the scanned machine.</summary>
    public required string ComputerName { get; init; }

    /// <summary>User account the scan ran as.</summary>
    public required string UserName { get; init; }

    /// <summary>Operating system description.</summary>
    public required string OperatingSystem { get; init; }

    /// <summary>When the scan started.</summary>
    public required DateTimeOffset ScanTime { get; init; }

    /// <summary>How long the scan took.</summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>Windows licensing result.</summary>
    public required WindowsLicenseInfo License { get; init; }

    /// <summary>Evaluated installed software, failures first.</summary>
    public required IReadOnlyList<ScanFinding> InstalledSoftware { get; init; }

    /// <summary>Evaluated portable software, failures first.</summary>
    public required IReadOnlyList<ScanFinding> PortableSoftware { get; init; }

    /// <summary>Non-fatal problems encountered during the scan, such as unreadable directories.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>The Windows license expressed as a finding, so it can be counted and exported uniformly.</summary>
    public ScanFinding LicenseFinding => new()
    {
        Name = this.License.Evidence.ProductName ?? "Windows",
        Publisher = "Microsoft Corporation",
        Version = this.License.Evidence.Version,
        Location = null,
        Status = this.License.Status,
        Reason = this.License.Reason,
        Category = "Windows License",
        Section = FindingSection.WindowsLicense,
    };

    /// <summary>Every finding in the report, including the Windows license.</summary>
    public IReadOnlyList<ScanFinding> AllFindings =>
    [
        this.LicenseFinding,
        .. this.InstalledSoftware,
        .. this.PortableSoftware,
    ];

    /// <summary>Total number of compliance checks performed.</summary>
    public int TotalChecks => this.AllFindings.Count;

    /// <summary>Number of checks that passed.</summary>
    public int PassCount => this.AllFindings.Count(f => f.Status == ComplianceStatus.Pass);

    /// <summary>Number of checks that failed.</summary>
    public int FailCount => this.AllFindings.Count(f => f.Status == ComplianceStatus.Fail);

    /// <summary>
    /// The overall verdict. Any single failure fails the machine.
    /// </summary>
    public ComplianceStatus OverallResult =>
        this.FailCount > 0 ? ComplianceStatus.Fail : ComplianceStatus.Pass;
}
