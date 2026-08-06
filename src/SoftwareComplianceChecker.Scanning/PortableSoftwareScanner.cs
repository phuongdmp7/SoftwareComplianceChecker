using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.Scanning;

/// <summary>
/// Finds executables running from disk that were never installed.
/// </summary>
/// <remarks>
/// The search is bounded by <see cref="PortableFolderOptions.MaxDepth"/>. An unbounded walk
/// of a large Downloads or Documents tree is the single largest threat to the scan budget,
/// and depth is the cheapest effective bound.
/// </remarks>
public sealed class PortableSoftwareScanner : IPortableSoftwareScanner
{
    private const string ExecutablePattern = "*.exe";

    private readonly IFileSystem fileSystem;
    private readonly PortableFolderOptions options;
    private readonly ILogger<PortableSoftwareScanner> logger;

    /// <summary>Creates the scanner.</summary>
    /// <param name="fileSystem">File system access.</param>
    /// <param name="options">Folders to search and the depth bound.</param>
    /// <param name="logger">Receives diagnostics.</param>
    public PortableSoftwareScanner(
        IFileSystem fileSystem,
        IOptions<PortableFolderOptions> options,
        ILogger<PortableSoftwareScanner> logger)
    {
        this.fileSystem = fileSystem;
        this.options = options.Value;
        this.logger = logger;
    }

    /// <inheritdoc />
    public Task<ScanOutcome<SoftwareItem>> ScanAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => this.Scan(cancellationToken), cancellationToken);

    private ScanOutcome<SoftwareItem> Scan(CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var items = new List<SoftwareItem>();
        var warnings = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var folder in this.options.Folders.Where(f => f.Enabled))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var expanded = this.fileSystem.ExpandPath(folder.Path);

            if (!this.fileSystem.DirectoryExists(expanded))
            {
                // A configured drive or folder simply not being present is normal, not an error.
                this.logger.LogDebug("Portable scan skipped missing folder {Folder}.", expanded);
                continue;
            }

            foreach (var file in this.fileSystem.EnumerateFiles(
                         expanded, this.options.MaxDepth, ExecutablePattern, cancellationToken))
            {
                if (!seen.Add(file))
                {
                    continue;
                }

                items.Add(CreateItem(file));
            }
        }

        stopwatch.Stop();

        this.logger.LogInformation(
            "Portable scan examined {Count} executables in {ElapsedMs} ms across {FolderCount} folder(s).",
            items.Count,
            stopwatch.ElapsedMilliseconds,
            this.options.Folders.Count(f => f.Enabled));

        return new ScanOutcome<SoftwareItem>(items, warnings);
    }

    private static SoftwareItem CreateItem(string path)
    {
        var fileName = Path.GetFileName(path);

        return new SoftwareItem
        {
            DisplayName = Path.GetFileNameWithoutExtension(path),
            ExecutableName = fileName,
            SourcePath = path,
            Source = SoftwareSource.Portable,
        };
    }
}
