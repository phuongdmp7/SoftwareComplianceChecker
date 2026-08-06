using System.Globalization;
using Microsoft.Extensions.Logging;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Rules;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Collects Windows licensing evidence and evaluates it.
/// </summary>
/// <remarks>
/// This scanner gathers facts only. The verdict is drawn by <see cref="KmsEvidenceEvaluator"/>,
/// which keeps the decision logic pure and testable.
/// </remarks>
public sealed class WindowsLicenseScanner : IWindowsLicenseScanner
{
    private const string WmiScope = @"root\CIMV2";

    /// <summary>Application identifier Windows itself is licensed under.</summary>
    private const string WindowsApplicationId = "55c92734-d682-4d71-983e-d6ec3f16059f";

    private const string CurrentVersionPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    private const string ProtectionPlatformPath = CurrentVersionPath + @"\SoftwareProtectionPlatform";

    private readonly IWmiQuery wmi;
    private readonly IRegistryReader registry;
    private readonly ActivationToolDetector toolDetector;
    private readonly IActivationToolPatternSource patternSource;
    private readonly ILogger<WindowsLicenseScanner> logger;

    /// <summary>Creates the scanner.</summary>
    /// <param name="wmi">WMI access.</param>
    /// <param name="registry">Registry access.</param>
    /// <param name="toolDetector">Activation tool detection.</param>
    /// <param name="patternSource">Supplies activation tool patterns from policy.</param>
    /// <param name="logger">Receives diagnostics.</param>
    public WindowsLicenseScanner(
        IWmiQuery wmi,
        IRegistryReader registry,
        ActivationToolDetector toolDetector,
        IActivationToolPatternSource patternSource,
        ILogger<WindowsLicenseScanner> logger)
    {
        this.wmi = wmi;
        this.registry = registry;
        this.toolDetector = toolDetector;
        this.patternSource = patternSource;
        this.logger = logger;
    }

    /// <inheritdoc />
    public Task<WindowsLicenseInfo> ScanAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => this.Scan(cancellationToken), cancellationToken);

    private WindowsLicenseInfo Scan(CancellationToken cancellationToken)
    {
        var warnings = new List<string>();

        var product = this.QueryWindowsProduct(warnings);
        var service = this.QueryLicensingService(warnings);
        var toolResult = this.toolDetector.Detect(this.patternSource.GetPatterns(), cancellationToken);

        warnings.AddRange(toolResult.Warnings);

        var kmsFromRegistry = this.registry.ReadValue(
            RegistryRoot.LocalMachine, ProtectionPlatformPath, "KeyManagementServiceName", RegistryBitness.Bit64);

        var kmsPortFromRegistry = this.registry.ReadValue(
            RegistryRoot.LocalMachine, ProtectionPlatformPath, "KeyManagementServicePort", RegistryBitness.Bit64);

        var evidence = new LicenseEvidence
        {
            Edition = this.ReadCurrentVersion("EditionID"),
            ProductName = this.ReadCurrentVersion("ProductName"),
            Version = this.ReadCurrentVersion("DisplayVersion") ?? this.ReadCurrentVersion("ReleaseId"),
            BuildNumber = this.BuildNumber(),

            LicenseStatusCode = GetInt(product, "LicenseStatus"),
            LicenseStatus = DescribeLicenseStatus(GetInt(product, "LicenseStatus")),
            ProductKeyChannel = GetString(product, "ProductKeyChannel"),
            LicenseDescription = GetString(product, "Description"),
            PartialProductKey = GetString(product, "PartialProductKey"),
            GracePeriodMinutes = GetInt(product, "GracePeriodRemaining"),

            OemBiosKeyPresent = !string.IsNullOrWhiteSpace(GetString(service, "OA3xOriginalProductKey")),

            KmsServerName = FirstNonEmpty(
                GetString(product, "KeyManagementServiceMachine"),
                GetString(service, "KeyManagementServiceMachine"),
                kmsFromRegistry),

            KmsServerPort = ParsePort(FirstNonEmpty(
                GetString(product, "KeyManagementServicePort"),
                GetString(service, "KeyManagementServicePort"),
                kmsPortFromRegistry)),

            ActivationToolTraces = toolResult.Items,
            InaccessibleSources = warnings,
        };

        var result = KmsEvidenceEvaluator.Evaluate(evidence);

        this.logger.LogInformation(
            "Windows license evaluated as {Status} ({ActivationType}) with {EvidenceCount} KMS indicator(s).",
            result.Status,
            result.ActivationType,
            result.KmsEvidence.Count);

        return result;
    }

    private IReadOnlyDictionary<string, object?>? QueryWindowsProduct(List<string> warnings)
    {
        // Filtering on PartialProductKey excludes the many inactive license slots Windows
        // registers; only the applied license carries one.
        var rows = this.wmi.Query(
            WmiScope,
            "SELECT Name, Description, PartialProductKey, LicenseStatus, GracePeriodRemaining, " +
            "ProductKeyChannel, LicenseFamily, KeyManagementServiceMachine, KeyManagementServicePort " +
            "FROM SoftwareLicensingProduct " +
            $"WHERE ApplicationID = '{WindowsApplicationId}' AND PartialProductKey IS NOT NULL");

        if (rows.Count != 0)
        {
            return rows[0];
        }

        warnings.Add(
            "No applied Windows license was found through WMI. The licensing verdict is based on " +
            "reduced evidence.");

        return null;
    }

    private IReadOnlyDictionary<string, object?>? QueryLicensingService(List<string> warnings)
    {
        var rows = this.wmi.Query(
            WmiScope,
            "SELECT OA3xOriginalProductKey, KeyManagementServiceMachine, KeyManagementServicePort, " +
            "ClientMachineID FROM SoftwareLicensingService");

        if (rows.Count != 0)
        {
            return rows[0];
        }

        warnings.Add("The Windows licensing service could not be queried through WMI.");
        return null;
    }

    private string? ReadCurrentVersion(string valueName) =>
        this.registry.ReadValue(RegistryRoot.LocalMachine, CurrentVersionPath, valueName, RegistryBitness.Bit64);

    private string? BuildNumber()
    {
        var build = this.ReadCurrentVersion("CurrentBuild");
        var revision = this.ReadCurrentVersion("UBR");

        if (string.IsNullOrWhiteSpace(build))
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(revision) ? build : $"{build}.{revision}";
    }

    private static string? FirstNonEmpty(params string?[] candidates) =>
        candidates.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c));

    private static int? ParsePort(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) ? port : null;

    private static string? GetString(IReadOnlyDictionary<string, object?>? row, string key) =>
        row is not null && row.TryGetValue(key, out var value) ? value?.ToString() : null;

    private static int? GetInt(IReadOnlyDictionary<string, object?>? row, string key)
    {
        if (row is null || !row.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }

        try
        {
            return Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    /// <summary>Maps the numeric licensing status Windows reports to readable text.</summary>
    private static string? DescribeLicenseStatus(int? code) => code switch
    {
        null => null,
        0 => "Unlicensed",
        1 => "Licensed",
        2 => "Out-of-box grace period",
        3 => "Out-of-tolerance grace period",
        4 => "Non-genuine grace period",
        5 => "Notification",
        6 => "Extended grace period",
        _ => $"Unknown ({code})",
    };
}
