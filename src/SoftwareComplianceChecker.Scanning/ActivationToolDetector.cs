using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Looks for traces of Windows activation tools across services, scheduled tasks and disk.
/// </summary>
/// <remarks>
/// <para>
/// The patterns are supplied by the caller from rules.json rather than hardcoded, so the
/// detection list is policy data like everything else.
/// </para>
/// <para>
/// Every hit is reported as a described observation rather than a bare boolean, so a FAIL
/// verdict can be audited. A file merely named like an activation tool is weak evidence, and
/// the report must let a reader judge that for themselves.
/// </para>
/// </remarks>
public sealed class ActivationToolDetector
{
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";

    private readonly IRegistryReader registry;
    private readonly IFileSystem fileSystem;

    /// <summary>Creates the detector.</summary>
    /// <param name="registry">Registry access.</param>
    /// <param name="fileSystem">File system access.</param>
    public ActivationToolDetector(IRegistryReader registry, IFileSystem fileSystem)
    {
        this.registry = registry;
        this.fileSystem = fileSystem;
    }

    /// <summary>
    /// Searches for activation tool traces.
    /// </summary>
    /// <param name="namePatterns">Tool names to look for, for example <c>KMSPico</c>.</param>
    /// <param name="cancellationToken">Cancels the search.</param>
    /// <returns>Described observations, and surfaces that could not be read.</returns>
    public ScanOutcome<string> Detect(
        IReadOnlyCollection<string> namePatterns,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(namePatterns);

        var traces = new List<string>();
        var warnings = new List<string>();

        if (namePatterns.Count == 0)
        {
            return new ScanOutcome<string>(traces, warnings);
        }

        traces.AddRange(this.DetectServices(namePatterns));
        traces.AddRange(this.DetectScheduledTasks(namePatterns, warnings, cancellationToken));
        traces.AddRange(this.DetectDirectories(namePatterns));

        return new ScanOutcome<string>(traces.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), warnings);
    }

    private IEnumerable<string> DetectServices(IReadOnlyCollection<string> namePatterns)
    {
        var serviceNames = this.registry.GetSubKeyNames(
            RegistryRoot.LocalMachine, ServicesPath, RegistryBitness.Bit64);

        foreach (var serviceName in serviceNames)
        {
            var match = FindMatch(serviceName, namePatterns);
            if (match is not null)
            {
                yield return $"A Windows service named '{serviceName}' matches the known activation tool '{match}'.";
            }
        }
    }

    private IEnumerable<string> DetectScheduledTasks(
        IReadOnlyCollection<string> namePatterns,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var tasksRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");

        if (!this.fileSystem.DirectoryExists(tasksRoot))
        {
            warnings.Add(
                "The scheduled task store could not be read. Run as administrator for a complete " +
                "activation tool check.");

            yield break;
        }

        foreach (var taskFile in this.fileSystem.EnumerateFiles(tasksRoot, maxDepth: 3, "*", cancellationToken))
        {
            var taskName = Path.GetFileName(taskFile);
            var match = FindMatch(taskName, namePatterns);

            if (match is not null)
            {
                yield return $"A scheduled task named '{taskName}' matches the known activation tool '{match}'.";
            }
        }
    }

    private IEnumerable<string> DetectDirectories(IReadOnlyCollection<string> namePatterns)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var root in roots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct())
        {
            foreach (var pattern in namePatterns)
            {
                // Only bare names can be directories; executable patterns are handled by the
                // portable scanner, which searches file names directly.
                if (pattern.Contains('.') || pattern.Contains('*'))
                {
                    continue;
                }

                var candidate = Path.Combine(root, pattern);

                if (this.fileSystem.DirectoryExists(candidate))
                {
                    yield return $"A directory named after the activation tool '{pattern}' exists at '{candidate}'.";
                }
            }
        }
    }

    private static string? FindMatch(string value, IEnumerable<string> namePatterns) =>
        namePatterns.FirstOrDefault(pattern =>
            !string.IsNullOrWhiteSpace(pattern)
            && value.Contains(StripExtension(pattern), StringComparison.OrdinalIgnoreCase));

    private static string StripExtension(string pattern) =>
        pattern.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? pattern[..^4]
            : pattern;
}
