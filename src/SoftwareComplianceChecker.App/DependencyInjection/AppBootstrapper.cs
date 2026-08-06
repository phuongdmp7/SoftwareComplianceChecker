using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SoftwareComplianceChecker.App.Logging;
using SoftwareComplianceChecker.App.ViewModels;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Export;
using SoftwareComplianceChecker.Rules;
using SoftwareComplianceChecker.Scanning;
using SoftwareComplianceChecker.Scanning.Platform;

namespace SoftwareComplianceChecker.App.DependencyInjection;

/// <summary>
/// Builds the application's service container.
/// </summary>
/// <remarks>
/// The single composition root. Nothing else resolves services from a container, so the
/// dependency graph is visible in one file.
/// </remarks>
public static class AppBootstrapper
{
    /// <summary>Directory the executable runs from, where configuration files live.</summary>
    public static string BaseDirectory => AppContext.BaseDirectory;

    /// <summary>
    /// Builds the service provider.
    /// </summary>
    /// <returns>A configured provider.</returns>
    /// <exception cref="RuleConfigurationException">The compliance policy could not be loaded.</exception>
    public static ServiceProvider Build()
    {
        var configuration = new ConfigurationBuilder()
            .SetBasePath(BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .Build();

        var services = new ServiceCollection();

        services.Configure<ScanOptions>(configuration.GetSection(ScanOptions.SectionName));
        services.Configure<LoggingOptions>(configuration.GetSection(LoggingOptions.SectionName));
        services.Configure<ExportOptions>(configuration.GetSection(ExportOptions.SectionName));

        AddLogging(services, configuration);
        AddPolicy(services);
        AddScanning(services);
        AddExport(services);

        services.AddSingleton<MainViewModel>();
        services.AddSingleton<MainWindow>();

        return services.BuildServiceProvider();
    }

    private static void AddLogging(IServiceCollection services, IConfiguration configuration)
    {
        var loggingOptions = new LoggingOptions();
        configuration.GetSection(LoggingOptions.SectionName).Bind(loggingOptions);

        var logDirectory = Path.IsPathRooted(loggingOptions.Directory)
            ? loggingOptions.Directory
            : Path.Combine(BaseDirectory, loggingOptions.Directory);

        var minimumLevel = Enum.TryParse<LogLevel>(loggingOptions.MinimumLevel, ignoreCase: true, out var level)
            ? level
            : LogLevel.Information;

        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(minimumLevel);
            builder.AddProvider(new FileLoggerProvider(logDirectory, minimumLevel, loggingOptions.RetentionDays));
        });
    }

    private static void AddPolicy(IServiceCollection services)
    {
        services.AddSingleton<IRuleSetLoader, JsonRuleSetLoader>();

        // Loaded once at startup. A malformed policy file is fatal by design: continuing with
        // no rules would report PASS for everything, which is worse than not running at all.
        services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<IOptions<ScanOptions>>().Value;
            var loader = provider.GetRequiredService<IRuleSetLoader>();

            return loader.Load(Path.Combine(BaseDirectory, options.RulesFile));
        });

        services.AddSingleton<IRuleEngine>(provider =>
            new RuleEngine(provider.GetRequiredService<RuleSet>()));

        services.AddSingleton<IActivationToolPatternSource>(provider =>
            new RuleSetActivationToolPatternSource(provider.GetRequiredService<RuleSet>()));
    }

    private static void AddScanning(IServiceCollection services)
    {
        services.AddSingleton<IRegistryReader, WindowsRegistryReader>();
        services.AddSingleton<IWmiQuery, WindowsWmiQuery>();
        services.AddSingleton<IFileSystem, PhysicalFileSystem>();
        services.AddSingleton<ISystemInfoProvider, SystemInfoProvider>();
        services.AddSingleton<ActivationToolDetector>();

        services.AddSingleton<IOptions<PortableFolderOptions>>(provider =>
        {
            var scanOptions = provider.GetRequiredService<IOptions<ScanOptions>>().Value;
            var path = Path.Combine(BaseDirectory, scanOptions.PortableFoldersFile);

            var (options, warning) = PortableFolderOptionsLoader.Load(path);

            if (warning is not null)
            {
                provider.GetRequiredService<ILoggerFactory>()
                        .CreateLogger(nameof(PortableFolderOptionsLoader))
                        .LogWarning("{Warning}", warning);
            }

            return Options.Create(options);
        });

        services.AddSingleton<IInstalledSoftwareScanner, InstalledSoftwareScanner>();
        services.AddSingleton<IPortableSoftwareScanner, PortableSoftwareScanner>();
        services.AddSingleton<IWindowsLicenseScanner, WindowsLicenseScanner>();
        services.AddSingleton<IComplianceScanService, ComplianceScanService>();
    }

    private static void AddExport(IServiceCollection services)
    {
        services.AddSingleton<IReportExporter, HtmlReportExporter>();
        services.AddSingleton<IReportExporter, CsvReportExporter>();
        services.AddSingleton<IReportExporter, JsonReportExporter>();
        services.AddSingleton<IReportExportService, ReportExportService>();
    }
}
