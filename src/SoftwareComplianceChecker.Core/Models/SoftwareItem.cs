namespace SoftwareComplianceChecker.Core.Models;

/// <summary>
/// A piece of software discovered on the machine, before any policy is applied.
/// </summary>
/// <remarks>
/// Scanners produce <see cref="SoftwareItem"/> values and take no view on compliance.
/// The rule engine alone decides <see cref="ComplianceStatus"/>.
/// </remarks>
public sealed record SoftwareItem
{
    /// <summary>Display name of the software, as reported by its source.</summary>
    public required string DisplayName { get; init; }

    /// <summary>Publisher or vendor, when known.</summary>
    public string? Publisher { get; init; }

    /// <summary>Version string, when known.</summary>
    public string? Version { get; init; }

    /// <summary>Installation directory, when known.</summary>
    public string? InstallLocation { get; init; }

    /// <summary>Uninstall command registered for the software, when known.</summary>
    public string? UninstallString { get; init; }

    /// <summary>Architecture the software was registered under, such as x64 or x86.</summary>
    public string? Architecture { get; init; }

    /// <summary>File name of the executable, set for portable software discovered on disk.</summary>
    public string? ExecutableName { get; init; }

    /// <summary>Full path the item was discovered at, set for portable software.</summary>
    public string? SourcePath { get; init; }

    /// <summary>Where this item was discovered.</summary>
    public required SoftwareSource Source { get; init; }

    /// <summary>The location shown in reports: install directory for installed software, file path for portable.</summary>
    public string? Location => this.Source == SoftwareSource.Portable ? this.SourcePath : this.InstallLocation;
}

/// <summary>
/// Where a <see cref="SoftwareItem"/> was discovered.
/// </summary>
public enum SoftwareSource
{
    /// <summary>Registered in the Windows uninstall registry keys.</summary>
    Installed = 0,

    /// <summary>Found as an executable on disk without being installed.</summary>
    Portable = 1,
}
