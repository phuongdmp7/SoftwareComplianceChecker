using System.Management;
using Microsoft.Extensions.Logging;
using SoftwareComplianceChecker.Core.Abstractions;

namespace SoftwareComplianceChecker.Scanning.Platform;

/// <summary>
/// Runs WMI queries against the local machine.
/// </summary>
/// <remarks>
/// The only type in the solution that touches WMI. Note that no query here uses
/// <c>Win32_Product</c>: reading that class triggers an MSI reconfiguration of every
/// installed package and is pathologically slow.
/// </remarks>
public sealed class WindowsWmiQuery : IWmiQuery
{
    private readonly ILogger<WindowsWmiQuery> logger;

    /// <summary>Creates the query runner.</summary>
    /// <param name="logger">Receives diagnostics for failed queries.</param>
    public WindowsWmiQuery(ILogger<WindowsWmiQuery> logger)
    {
        this.logger = logger;
    }

    /// <inheritdoc />
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string query)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(query);

        var rows = new List<IReadOnlyDictionary<string, object?>>();

        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(query));
            using var results = searcher.Get();

            foreach (var item in results)
            {
                using var managementObject = (ManagementObject)item;
                var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

                foreach (var property in managementObject.Properties)
                {
                    row[property.Name] = property.Value;
                }

                rows.Add(row);
            }
        }
        catch (ManagementException ex)
        {
            this.logger.LogWarning(ex, "WMI query failed against {Scope}: {Query}", scope, query);
            return [];
        }
        catch (UnauthorizedAccessException ex)
        {
            this.logger.LogWarning(ex, "Access denied running WMI query against {Scope}: {Query}", scope, query);
            return [];
        }

        return rows;
    }
}
