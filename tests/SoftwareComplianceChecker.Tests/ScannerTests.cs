using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using SoftwareComplianceChecker.Core.Abstractions;
using SoftwareComplianceChecker.Core.Configuration;
using SoftwareComplianceChecker.Scanning;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Scanner behaviour that does not depend on Windows: filtering, deduplication, and the
/// depth bound that keeps the portable scan inside its budget.
/// </summary>
public sealed class ScannerTests
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    private static RegistryKeyData Entry(string keyName, params (string Name, string? Value)[] values) =>
        new(keyName, values.ToDictionary(v => v.Name, v => v.Value, StringComparer.OrdinalIgnoreCase));

    private static InstalledSoftwareScanner CreateInstalledScanner(
        FakeRegistryReader registry,
        bool includeSystemComponents = false) =>
        new(registry,
            Options.Create(new ScanOptions { IncludeSystemComponents = includeSystemComponents }),
            NullLogger<InstalledSoftwareScanner>.Instance);

    [Fact]
    public async Task Entries_without_a_display_name_are_skipped()
    {
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("{guid}", ("DisplayVersion", "1.0")));

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task System_components_are_excluded_by_default()
    {
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("a", ("DisplayName", "Runtime Bits"), ("SystemComponent", "1")));

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task System_components_are_included_when_configured()
    {
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("a", ("DisplayName", "Runtime Bits"), ("SystemComponent", "1")));

        var result = await CreateInstalledScanner(registry, includeSystemComponents: true).ScanAsync();

        result.Items.Count.ShouldBe(1);
    }

    [Fact]
    public async Task Update_entries_with_a_parent_key_are_skipped()
    {
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("kb", ("DisplayName", "Update for Thing"), ("ParentKeyName", "OtherProduct")));

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task Both_registry_views_are_read()
    {
        // Reading only the 64-bit view silently misses every 32-bit install.
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("a", ("DisplayName", "Sixty Four")));
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit32,
            Entry("b", ("DisplayName", "Thirty Two")));

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.Select(i => i.DisplayName).ShouldBe(["Sixty Four", "Thirty Two"], ignoreOrder: true);
    }

    [Fact]
    public async Task The_same_product_registered_twice_is_reported_once()
    {
        var registry = new FakeRegistryReader();

        foreach (var bitness in new[] { RegistryBitness.Bit64, RegistryBitness.Bit32 })
        {
            registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, bitness,
                Entry("a", ("DisplayName", "Shared App"), ("DisplayVersion", "2.0"), ("Publisher", "Acme")));
        }

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.Count.ShouldBe(1);
    }

    [Fact]
    public async Task Installed_results_are_sorted_by_name()
    {
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("a", ("DisplayName", "Zebra")));
        registry.AddSubKey(RegistryRoot.LocalMachine, UninstallPath, RegistryBitness.Bit64,
            Entry("b", ("DisplayName", "Alpha")));

        var result = await CreateInstalledScanner(registry).ScanAsync();

        result.Items.Select(i => i.DisplayName).ShouldBe(["Alpha", "Zebra"]);
    }

    [Fact]
    public async Task Portable_scan_respects_the_depth_bound()
    {
        // The depth bound is what keeps a large Downloads tree from blowing the scan budget.
        var fileSystem = new FakeFileSystem();
        fileSystem.AddFile(@"C:\Tools", "top.exe");
        fileSystem.AddFile(@"C:\Tools\one", "depth1.exe");
        fileSystem.AddFile(@"C:\Tools\one\two", "depth2.exe");
        fileSystem.AddFile(@"C:\Tools\one\two\three", "depth3.exe");

        var options = new PortableFolderOptions
        {
            MaxDepth = 2,
            Folders = [new PortableFolder { Path = @"C:\Tools" }],
        };

        var scanner = new PortableSoftwareScanner(
            fileSystem, Options.Create(options), NullLogger<PortableSoftwareScanner>.Instance);

        var result = await scanner.ScanAsync();

        result.Items.Select(i => i.ExecutableName)
              .ShouldBe(["top.exe", "depth1.exe", "depth2.exe"], ignoreOrder: true);
    }

    [Fact]
    public async Task Disabled_folders_are_not_searched()
    {
        var fileSystem = new FakeFileSystem();
        fileSystem.AddFile(@"C:\Tools", "tool.exe");

        var options = new PortableFolderOptions
        {
            MaxDepth = 3,
            Folders = [new PortableFolder { Path = @"C:\Tools", Enabled = false }],
        };

        var scanner = new PortableSoftwareScanner(
            fileSystem, Options.Create(options), NullLogger<PortableSoftwareScanner>.Instance);

        var result = await scanner.ScanAsync();

        result.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_missing_folder_is_skipped_without_failing_the_scan()
    {
        // Configured drives such as D:\ or E:\ are routinely absent; that is normal, not an error.
        var fileSystem = new FakeFileSystem();
        fileSystem.AddFile(@"C:\Tools", "tool.exe");

        var options = new PortableFolderOptions
        {
            MaxDepth = 2,
            Folders =
            [
                new PortableFolder { Path = @"C:\Tools" },
                new PortableFolder { Path = @"E:\Apps" },
            ],
        };

        var scanner = new PortableSoftwareScanner(
            fileSystem, Options.Create(options), NullLogger<PortableSoftwareScanner>.Instance);

        var result = await scanner.ScanAsync();

        result.Items.Count.ShouldBe(1);
    }

    [Fact]
    public void Activation_tool_detection_reports_a_described_observation()
    {
        // A bare boolean would make a FAIL unauditable; the report must say what was found.
        var registry = new FakeRegistryReader();
        registry.AddSubKey(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Services",
            RegistryBitness.Bit64, new RegistryKeyData("AutoKMS", new Dictionary<string, string?>()));

        var detector = new ActivationToolDetector(registry, new FakeFileSystem());

        var result = detector.Detect(["AutoKMS", "KMSPico"]);

        result.Items.ShouldContain(t => t.Contains("AutoKMS", StringComparison.Ordinal));
    }

    [Fact]
    public void Activation_tool_detection_finds_nothing_on_a_clean_machine()
    {
        var detector = new ActivationToolDetector(new FakeRegistryReader(), new FakeFileSystem());

        var result = detector.Detect(["AutoKMS", "KMSPico"]);

        result.Items.ShouldBeEmpty();
    }
}
