using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Runs every scanner, applies the policy, and assembles the report.
/// </summary>
public sealed class ComplianceScanService : IComplianceScanService
{
    private readonly IWindowsLicenseScanner licenseScanner;
    private readonly IInstalledSoftwareScanner installedScanner;
    private readonly IPortableSoftwareScanner portableScanner;
    private readonly IRuleEngine ruleEngine;
    private readonly ISystemInfoProvider systemInfo;
    private readonly ScanOptions options;
    private readonly ILogger<ComplianceScanService> logger;

    /// <summary>Creates the service.</summary>
    /// <param name="licenseScanner">Windows licensing scanner.</param>
    /// <param name="installedScanner">Installed software scanner.</param>
    /// <param name="portableScanner">Portable software scanner.</param>
    /// <param name="ruleEngine">Policy engine.</param>
    /// <param name="systemInfo">Machine description.</param>
    /// <param name="options">Scan settings.</param>
    /// <param name="logger">Receives diagnostics and timings.</param>
    public ComplianceScanService(
        IWindowsLicenseScanner licenseScanner,
        IInstalledSoftwareScanner installedScanner,
        IPortableSoftwareScanner portableScanner,
        IRuleEngine ruleEngine,
        ISystemInfoProvider systemInfo,
        IOptions<ScanOptions> options,
        ILogger<ComplianceScanService> logger)
    {
        this.licenseScanner = licenseScanner;
        this.installedScanner = installedScanner;
        this.portableScanner = portableScanner;
        this.ruleEngine = ruleEngine;
        this.systemInfo = systemInfo;
        this.options = options.Value;
        this.logger = logger;
    }

    /// <inheritdoc />
    public async Task<ComplianceReport> ScanAsync(
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.Now;
        var stopwatch = Stopwatch.StartNew();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(this.options.TimeoutSeconds));
        var token = timeout.Token;

        progress?.Report("Scanning...");

        // The three scanners touch different subsystems and share no state, so running them
        // concurrently is what keeps the whole scan inside its budget. WMI is the slowest of
        // the three and would otherwise dominate.
        var licenseTask = this.licenseScanner.ScanAsync(token);
        var installedTask = this.installedScanner.ScanAsync(token);
        var portableTask = this.portableScanner.ScanAsync(token);

        await Task.WhenAll(licenseTask, installedTask, portableTask).ConfigureAwait(false);

        var license = await licenseTask.ConfigureAwait(false);
        var installed = await installedTask.ConfigureAwait(false);
        var portable = await portableTask.ConfigureAwait(false);

        progress?.Report("Applying compliance policy...");

        var warnings = new List<string>();
        warnings.AddRange(installed.Warnings);
        warnings.AddRange(portable.Warnings);
        warnings.AddRange(license.Evidence.InaccessibleSources);

        if (!this.systemInfo.IsElevated)
        {
            warnings.Add(
                "The scan ran without administrative rights. Some evidence, such as scheduled tasks, " +
                "may not have been readable.");
        }

        var installedFindings = this.Evaluate(installed.Items, FindingSection.InstalledSoftware);

        // Every executable in Downloads or Documents is a candidate, but listing the passing
        // ones would bury the report in hundreds of irrelevant rows. Only violations are
        // reported; the count examined is logged instead.
        var portableFindings = this.Evaluate(portable.Items, FindingSection.PortableSoftware)
            .Where(f => f.Status == ComplianceStatus.Fail)
            .ToArray();

        if (this.ruleEngine is Rules.RuleEngine engine && engine.Diagnostics.Count > 0)
        {
            warnings.AddRange(engine.Diagnostics);
        }

        stopwatch.Stop();

        this.logger.LogInformation(
            "Scan completed in {ElapsedMs} ms: {Installed} installed entries, " +
            "{PortableExamined} portable executables examined, {PortableFailures} portable violations.",
            stopwatch.ElapsedMilliseconds,
            installed.Items.Count,
            portable.Items.Count,
            portableFindings.Length);

        progress?.Report("Done.");

        return new ComplianceReport
        {
            ComputerName = this.systemInfo.ComputerName,
            UserName = this.systemInfo.UserName,
            OperatingSystem = this.systemInfo.OperatingSystem,
            ScanTime = startedAt,
            Duration = stopwatch.Elapsed,
            License = license,
            InstalledSoftware = installedFindings,
            PortableSoftware = portableFindings,
            Warnings = warnings,
        };
    }

    private ScanFinding[] Evaluate(IReadOnlyList<SoftwareItem> items, FindingSection section)
    {
        return items
            .Select(item =>
            {
                var verdict = this.ruleEngine.Evaluate(item);

                return new ScanFinding
                {
                    Name = item.DisplayName,
                    Publisher = item.Publisher,
                    Version = item.Version,
                    Location = item.Location,
                    Status = verdict.Status,
                    Reason = verdict.Reason,
                    Category = verdict.Category,
                    MatchedRule = verdict.RuleName,
                    Section = section,
                };
            })

            // Failures first, then alphabetical, so the report leads with what needs action.
            .OrderByDescending(f => f.Status == ComplianceStatus.Fail)
            .ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
