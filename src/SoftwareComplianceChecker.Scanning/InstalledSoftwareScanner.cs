using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Enumerates installed software from the Windows uninstall registry keys.
/// </summary>
/// <remarks>
/// The registry is read rather than <c>Win32_Product</c>: querying that WMI class triggers a
/// consistency check and reconfiguration of every installed MSI package, which is slow enough
/// to blow the scan budget on its own and can alter machine state.
/// </remarks>
public sealed class InstalledSoftwareScanner : IInstalledSoftwareScanner
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>Registry release types that describe patches rather than user-facing software.</summary>
    private static readonly string[] ExcludedReleaseTypes =
    [
        "Security Update", "Update Rollup", "Hotfix", "ServicePack",
    ];

    private readonly IRegistryReader registry;
    private readonly ScanOptions options;
    private readonly ILogger<InstalledSoftwareScanner> logger;

    /// <summary>Creates the scanner.</summary>
    /// <param name="registry">Registry access.</param>
    /// <param name="options">Scan settings.</param>
    /// <param name="logger">Receives diagnostics.</param>
    public InstalledSoftwareScanner(
        IRegistryReader registry,
        IOptions<ScanOptions> options,
        ILogger<InstalledSoftwareScanner> logger)
    {
        this.registry = registry;
        this.options = options.Value;
        this.logger = logger;
    }

    /// <inheritdoc />
    public Task<ScanOutcome<SoftwareItem>> ScanAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => this.Scan(cancellationToken), cancellationToken);

    private ScanOutcome<SoftwareItem> Scan(CancellationToken cancellationToken)
    {
        // Both registry views must be read. On 64-bit Windows the 32-bit view resolves to
        // WOW6432Node; reading only one view silently misses half the installed software.
        var sources = new (RegistryRoot Root, RegistryBitness Bitness)[]
        {
            (RegistryRoot.LocalMachine, RegistryBitness.Bit64),
            (RegistryRoot.LocalMachine, RegistryBitness.Bit32),
            (RegistryRoot.CurrentUser, RegistryBitness.Bit64),
            (RegistryRoot.CurrentUser, RegistryBitness.Bit32),
        };

        var deduplicated = new Dictionary<string, SoftwareItem>(StringComparer.OrdinalIgnoreCase);

        foreach (var (root, bitness) in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var key in this.registry.EnumerateSubKeys(root, UninstallPath, bitness))
            {
                var item = TryCreateItem(key, bitness, this.options.IncludeSystemComponents);
                if (item is null)
                {
                    continue;
                }

                deduplicated.TryAdd(BuildKey(item), item);
            }
        }

        var items = deduplicated.Values
            .OrderBy(i => i.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        this.logger.LogInformation("Installed software scan found {Count} entries.", items.Length);

        return ScanOutcome<SoftwareItem>.Success(items);
    }

    private static SoftwareItem? TryCreateItem(RegistryKeyData key, RegistryBitness bitness, bool includeSystemComponents)
    {
        var values = key.Values;

        var displayName = Get(values, "DisplayName");

        // Entries without a display name are not user-facing software.
        if (string.IsNullOrWhiteSpace(displayName))
        {
            return null;
        }

        if (!includeSystemComponents && IsSystemComponent(values))
        {
            return null;
        }

        // A parent key means this entry is an update to another product, not a product.
        if (!string.IsNullOrWhiteSpace(Get(values, "ParentKeyName")))
        {
            return null;
        }

        var releaseType = Get(values, "ReleaseType");
        if (releaseType is not null
            && ExcludedReleaseTypes.Contains(releaseType, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SoftwareItem
        {
            DisplayName = displayName.Trim(),
            Publisher = Get(values, "Publisher")?.Trim(),
            Version = Get(values, "DisplayVersion")?.Trim(),
            InstallLocation = Get(values, "InstallLocation")?.Trim(),
            UninstallString = Get(values, "UninstallString")?.Trim(),
            Architecture = bitness == RegistryBitness.Bit32 ? "x86" : "x64",
            Source = SoftwareSource.Installed,
        };
    }

    private static bool IsSystemComponent(IReadOnlyDictionary<string, string?> values) =>
        Get(values, "SystemComponent") is { } flag
        && (flag == "1" || string.Equals(flag, "True", StringComparison.OrdinalIgnoreCase));

    private static string? Get(IReadOnlyDictionary<string, string?> values, string name) =>
        values.TryGetValue(name, out var value) ? value : null;

    private static string BuildKey(SoftwareItem item) =>
        $"{item.DisplayName}|{item.Version}|{item.Publisher}";
}
