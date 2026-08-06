namespace SoftwareComplianceChecker.Core.Configuration;

/// <summary>
/// Scan settings, bound from the <c>Scan</c> section of appsettings.json.
/// </summary>
public sealed class ScanOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Scan";

    /// <summary>Rules file name, resolved relative to the application directory.</summary>
    public string RulesFile { get; set; } = "rules.json";

    /// <summary>Portable folder configuration file name, resolved relative to the application directory.</summary>
    public string PortableFoldersFile { get; set; } = "portableFolders.json";

    /// <summary>Overall scan timeout in seconds.</summary>
    public int TimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Whether to include registry entries flagged as system components.
    /// </summary>
    /// <remarks>
    /// These are hotfixes, runtimes and driver packages rather than user-facing software.
    /// Including them adds thousands of irrelevant rows to the report.
    /// </remarks>
    public bool IncludeSystemComponents { get; set; }
}

/// <summary>
/// Logging settings, bound from the <c>Logging</c> section of appsettings.json.
/// </summary>
public sealed class LoggingOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Logging";

    /// <summary>Log directory, resolved relative to the application directory.</summary>
    public string Directory { get; set; } = "logs";

    /// <summary>Minimum level to record.</summary>
    public string MinimumLevel { get; set; } = "Information";

    /// <summary>Days to keep log files before deleting them.</summary>
    public int RetentionDays { get; set; } = 30;
}

/// <summary>
/// Export settings, bound from the <c>Export</c> section of appsettings.json.
/// </summary>
public sealed class ExportOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Export";

    /// <summary>Default directory offered in the export dialog.</summary>
    public string DefaultDirectory { get; set; } = "reports";
}

/// <summary>A folder to search for portable software.</summary>
public sealed class PortableFolder
{
    /// <summary>Path, which may contain environment variables such as <c>%USERPROFILE%</c>.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>Whether this folder is searched.</summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// Portable scan configuration, loaded from portableFolders.json.
/// </summary>
public sealed class PortableFolderOptions
{
    /// <summary>
    /// Maximum directory levels to descend below each configured folder.
    /// </summary>
    /// <remarks>
    /// Bounded because an unbounded walk of a large Documents or Downloads tree is the
    /// single largest threat to the ten-second scan budget.
    /// </remarks>
    public int MaxDepth { get; set; } = 3;

    /// <summary>Folders to search.</summary>
    public List<PortableFolder> Folders { get; set; } = [];
}
