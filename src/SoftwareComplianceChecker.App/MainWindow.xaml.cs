using System.Windows;
using SoftwareComplianceChecker.App.ViewModels;

namespace SoftwareComplianceChecker.App;

/// <summary>
/// The dashboard window.
/// </summary>
public partial class MainWindow : Window
{
    /// <summary>Creates the window and binds it to its view model.</summary>
    /// <param name="viewModel">The dashboard view model.</param>
    public MainWindow(MainViewModel viewModel)
    {
        this.InitializeComponent();
        this.DataContext = viewModel;
    }
}
