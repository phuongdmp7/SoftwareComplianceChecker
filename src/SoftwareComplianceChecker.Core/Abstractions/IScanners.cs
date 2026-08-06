using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Core.Abstractions;

/// <summary>
/// Discovers software registered in the Windows uninstall registry keys.
/// </summary>
public interface IInstalledSoftwareScanner
{
    /// <summary>Enumerates installed software. Never applies policy.</summary>
    /// <param name="cancellationToken">Cancels the scan.</param>
    Task<ScanOutcome<SoftwareItem>> ScanAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Discovers executables running from disk without having been installed.
/// </summary>
public interface IPortableSoftwareScanner
{
    /// <summary>Enumerates portable software in the configured folders. Never applies policy.</summary>
    /// <param name="cancellationToken">Cancels the scan.</param>
    Task<ScanOutcome<SoftwareItem>> ScanAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Collects Windows licensing evidence and evaluates it.
/// </summary>
public interface IWindowsLicenseScanner
{
    /// <summary>Gathers licensing evidence and derives a verdict from it.</summary>
    /// <param name="cancellationToken">Cancels the scan.</param>
    Task<WindowsLicenseInfo> ScanAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Runs every scanner and assembles the report.
/// </summary>
public interface IComplianceScanService
{
    /// <summary>Performs a full compliance scan.</summary>
    /// <param name="progress">Receives human-readable progress messages.</param>
    /// <param name="cancellationToken">Cancels the scan.</param>
    Task<ComplianceReport> ScanAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// The result of a scan that may have partially failed.
/// </summary>
/// <typeparam name="T">Type of discovered item.</typeparam>
/// <remarks>
/// A scanner that cannot read one surface, typically for lack of elevation, still returns
/// what it did find and reports the gap. Silently returning an empty list would turn a
/// permissions problem into a false PASS.
/// </remarks>
/// <param name="Items">Items successfully discovered.</param>
/// <param name="Warnings">Surfaces that could not be read, described for the report.</param>
public sealed record ScanOutcome<T>(IReadOnlyList<T> Items, IReadOnlyList<string> Warnings)
{
    /// <summary>An outcome with no warnings.</summary>
    /// <param name="items">Items successfully discovered.</param>
    public static ScanOutcome<T> Success(IReadOnlyList<T> items) => new(items, []);
}
