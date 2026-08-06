using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Core.Models;

namespace SoftwareComplianceChecker.App.ViewModels;

/// <summary>
/// Drives the dashboard: runs scans, exposes filtered findings, and exports reports.
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    /// <summary>Filter value meaning "do not filter on this field".</summary>
    public const string AnyValue = "All";

    private readonly IComplianceScanService scanService;
    private readonly IReportExportService exportService;
    private readonly ISystemLauncher systemLauncher;
    private readonly ExportOptions exportOptions;
    private readonly ILogger<MainViewModel> logger;

    private CancellationTokenSource? scanCancellation;

    [ObservableProperty]
    private bool isScanning;

    [ObservableProperty]
    private string statusMessage = "Ready. Press Scan to audit this machine.";

    [ObservableProperty]
    private ComplianceReport? report;

    [ObservableProperty]
    private string searchText = string.Empty;

    [ObservableProperty]
    private string selectedStatus = AnyValue;

    [ObservableProperty]
    private string selectedCategory = AnyValue;

    [ObservableProperty]
    private string selectedPublisher = AnyValue;

    /// <summary>Creates the view model.</summary>
    /// <param name="scanService">Runs compliance scans.</param>
    /// <param name="exportService">Writes reports.</param>
    /// <param name="systemLauncher">Opens Windows locations on the user's behalf.</param>
    /// <param name="exportOptions">Export settings.</param>
    /// <param name="logger">Receives diagnostics.</param>
    public MainViewModel(
        IComplianceScanService scanService,
        IReportExportService exportService,
        ISystemLauncher systemLauncher,
        IOptions<ExportOptions> exportOptions,
        ILogger<MainViewModel> logger)
    {
        this.scanService = scanService;
        this.exportService = exportService;
        this.systemLauncher = systemLauncher;
        this.exportOptions = exportOptions.Value;
        this.logger = logger;

        this.InstalledView = CollectionViewSource.GetDefaultView(this.InstalledFindings);
        this.InstalledView.Filter = this.MatchesFilters;

        this.PortableView = new CollectionViewSource { Source = this.PortableFindings }.View;
        this.PortableView.Filter = this.MatchesFilters;
    }

    /// <summary>Installed software findings, failures first.</summary>
    public ObservableCollection<ScanFinding> InstalledFindings { get; } = [];

    /// <summary>Portable software violations.</summary>
    public ObservableCollection<ScanFinding> PortableFindings { get; } = [];

    /// <summary>Filtered view over <see cref="InstalledFindings"/>.</summary>
    public ICollectionView InstalledView { get; }

    /// <summary>Filtered view over <see cref="PortableFindings"/>.</summary>
    public ICollectionView PortableView { get; }

    /// <summary>Status filter choices.</summary>
    public IReadOnlyList<string> StatusOptions { get; } = [AnyValue, "Pass", "Fail"];

    /// <summary>Category filter choices, populated after a scan.</summary>
    public ObservableCollection<string> CategoryOptions { get; } = [AnyValue];

    /// <summary>Publisher filter choices, populated after a scan.</summary>
    public ObservableCollection<string> PublisherOptions { get; } = [AnyValue];

    /// <summary>Whether a completed report is available.</summary>
    public bool HasReport => this.Report is not null;

    /// <summary>Overall verdict text, or a placeholder before the first scan.</summary>
    public string OverallResultText =>
        this.Report is null ? "—" : this.Report.OverallResult.ToString().ToUpperInvariant();

    /// <summary>Whether the overall verdict is a failure, used for accent colouring.</summary>
    public bool OverallFailed => this.Report?.OverallResult == ComplianceStatus.Fail;

    /// <summary>Total number of checks performed.</summary>
    public string TotalChecksText => this.Report?.TotalChecks.ToString() ?? "—";

    /// <summary>Number of checks that passed.</summary>
    public string PassCountText => this.Report?.PassCount.ToString() ?? "—";

    /// <summary>Number of checks that failed.</summary>
    public string FailCountText => this.Report?.FailCount.ToString() ?? "—";

    /// <summary>The Windows licensing result, once a scan has run.</summary>
    public WindowsLicenseInfo? License => this.Report?.License;

    /// <summary>Runs a compliance scan.</summary>
    [RelayCommand(CanExecute = nameof(CanScan))]
    private async Task ScanAsync()
    {
        this.IsScanning = true;
        this.StatusMessage = "Scanning...";
        this.scanCancellation = new CancellationTokenSource();

        try
        {
            var progress = new Progress<string>(message => this.StatusMessage = message);
            var result = await this.scanService.ScanAsync(progress, this.scanCancellation.Token)
                                               .ConfigureAwait(true);

            this.ApplyReport(result);

            this.StatusMessage =
                $"Scan finished in {result.Duration.TotalSeconds:F1} s — " +
                $"{result.FailCount} failed, {result.PassCount} passed.";
        }
        catch (OperationCanceledException)
        {
            this.StatusMessage = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            this.logger.LogError(ex, "The scan failed.");
            this.StatusMessage = $"Scan failed: {ex.Message}";
        }
        finally
        {
            this.scanCancellation?.Dispose();
            this.scanCancellation = null;
            this.IsScanning = false;
        }
    }

    private bool CanScan() => !this.IsScanning;

    /// <summary>Cancels a running scan.</summary>
    [RelayCommand(CanExecute = nameof(IsScanning))]
    private void CancelScan() => this.scanCancellation?.Cancel();

    /// <summary>Exports the current report in the named format.</summary>
    /// <param name="format">One of <c>Html</c>, <c>Csv</c> or <c>Json</c>.</param>
    [RelayCommand(CanExecute = nameof(HasReport))]
    private async Task ExportAsync(string format)
    {
        if (this.Report is null || !Enum.TryParse<ReportFormat>(format, ignoreCase: true, out var reportFormat))
        {
            return;
        }

        var suggested = this.exportService.SuggestFileName(this.Report, reportFormat);

        var dialog = new SaveFileDialog
        {
            FileName = suggested,
            Filter = DescribeFilter(reportFormat),
            InitialDirectory = this.ResolveExportDirectory(),
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            await this.exportService.ExportAsync(this.Report, reportFormat, dialog.FileName)
                                    .ConfigureAwait(true);

            this.StatusMessage = $"Report exported to {dialog.FileName}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            this.logger.LogError(ex, "Export failed.");
            this.StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    /// <summary>
    /// Opens the Windows screen where applications are uninstalled.
    /// </summary>
    /// <remarks>
    /// The application deliberately does not run uninstall strings itself. Removing software
    /// is the user's decision, made in Windows' own interface, where it can be reviewed and
    /// cancelled.
    /// </remarks>
    [RelayCommand]
    private void OpenInstalledApplications() =>
        this.StatusMessage = this.systemLauncher.OpenInstalledApplications().Message;

    /// <summary>
    /// Opens File Explorer with the finding's file selected.
    /// </summary>
    /// <param name="finding">The finding whose location should be revealed.</param>
    [RelayCommand(CanExecute = nameof(CanReveal))]
    private void Reveal(ScanFinding? finding) =>
        this.StatusMessage = this.systemLauncher.RevealInFileExplorer(finding?.Location).Message;

    private static bool CanReveal(ScanFinding? finding) => !string.IsNullOrWhiteSpace(finding?.Location);

    private void ApplyReport(ComplianceReport result)
    {
        this.Report = result;

        this.InstalledFindings.Clear();
        foreach (var finding in result.InstalledSoftware)
        {
            this.InstalledFindings.Add(finding);
        }

        this.PortableFindings.Clear();
        foreach (var finding in result.PortableSoftware)
        {
            this.PortableFindings.Add(finding);
        }

        RebuildOptions(this.CategoryOptions, result.AllFindings.Select(f => f.Category));
        RebuildOptions(this.PublisherOptions, result.AllFindings.Select(f => f.Publisher));

        this.SelectedCategory = AnyValue;
        this.SelectedPublisher = AnyValue;

        this.OnPropertyChanged(nameof(this.HasReport));
        this.OnPropertyChanged(nameof(this.OverallResultText));
        this.OnPropertyChanged(nameof(this.OverallFailed));
        this.OnPropertyChanged(nameof(this.TotalChecksText));
        this.OnPropertyChanged(nameof(this.PassCountText));
        this.OnPropertyChanged(nameof(this.FailCountText));
        this.OnPropertyChanged(nameof(this.License));

        this.ExportCommand.NotifyCanExecuteChanged();
        this.RefreshViews();
    }

    private static void RebuildOptions(ObservableCollection<string> target, IEnumerable<string?> values)
    {
        var distinct = values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        target.Clear();
        target.Add(AnyValue);

        foreach (var value in distinct)
        {
            target.Add(value);
        }
    }

    private bool MatchesFilters(object item)
    {
        if (item is not ScanFinding finding)
        {
            return false;
        }

        if (!string.Equals(this.SelectedStatus, AnyValue, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(finding.Status.ToString(), this.SelectedStatus, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(this.SelectedCategory, AnyValue, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(finding.Category, this.SelectedCategory, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(this.SelectedPublisher, AnyValue, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(finding.Publisher, this.SelectedPublisher, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.SearchText))
        {
            return true;
        }

        return Contains(finding.Name, this.SearchText)
               || Contains(finding.Publisher, this.SearchText)
               || Contains(finding.Location, this.SearchText)
               || Contains(finding.Reason, this.SearchText);
    }

    private static bool Contains(string? value, string needle) =>
        !string.IsNullOrEmpty(value) && value.Contains(needle, StringComparison.OrdinalIgnoreCase);

    private void RefreshViews()
    {
        this.InstalledView.Refresh();
        this.PortableView.Refresh();
    }

    private string ResolveExportDirectory()
    {
        var directory = Path.IsPathRooted(this.exportOptions.DefaultDirectory)
            ? this.exportOptions.DefaultDirectory
            : Path.Combine(AppContext.BaseDirectory, this.exportOptions.DefaultDirectory);

        Directory.CreateDirectory(directory);

        return directory;
    }

    private static string DescribeFilter(ReportFormat format) => format switch
    {
        ReportFormat.Html => "HTML report (*.html)|*.html",
        ReportFormat.Csv => "CSV report (*.csv)|*.csv",
        ReportFormat.Json => "JSON report (*.json)|*.json",
        _ => "All files (*.*)|*.*",
    };

    partial void OnSearchTextChanged(string value) => this.RefreshViews();

    partial void OnSelectedStatusChanged(string value) => this.RefreshViews();

    partial void OnSelectedCategoryChanged(string value) => this.RefreshViews();

    partial void OnSelectedPublisherChanged(string value) => this.RefreshViews();

    partial void OnIsScanningChanged(bool value)
    {
        this.ScanCommand.NotifyCanExecuteChanged();
        this.CancelScanCommand.NotifyCanExecuteChanged();
    }
}
