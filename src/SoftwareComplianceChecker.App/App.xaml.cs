using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using SoftwareComplianceChecker.App.DependencyInjection;
using SoftwareComplianceChecker.Rules;

namespace SoftwareComplianceChecker.App;

/// <summary>
/// Application entry point and service container owner.
/// </summary>
public partial class App : Application
{
    private ServiceProvider? services;

    /// <inheritdoc />
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            this.services = AppBootstrapper.Build();
        }
        catch (RuleConfigurationException ex)
        {
            // Without a valid policy the application would report PASS for everything.
            // Refusing to start is the honest outcome.
            MessageBox.Show(
                ex.Message,
                "Compliance policy could not be loaded",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            this.Shutdown(1);
            return;
        }

        var window = this.services.GetRequiredService<MainWindow>();
        this.MainWindow = window;
        window.Show();
    }

    /// <inheritdoc />
    protected override void OnExit(ExitEventArgs e)
    {
        this.services?.Dispose();
        base.OnExit(e);
    }
}
