using Shouldly;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Rules;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// The rule engine decides every compliance verdict, so a silent regression here changes
/// what the product reports. These tests cover each match type, the resolution order, and
/// the default-allow behaviour.
/// </summary>
public sealed class RuleEngineTests
{
    private static SoftwareItem Installed(string name, string? publisher = null, string? location = null) => new()
    {
        DisplayName = name,
        Publisher = publisher,
        InstallLocation = location,
        Source = SoftwareSource.Installed,
    };

    private static SoftwareItem Portable(string executable, string path = @"C:\Tools\app.exe") => new()
    {
        DisplayName = Path.GetFileNameWithoutExtension(executable),
        ExecutableName = executable,
        SourcePath = path,
        Source = SoftwareSource.Portable,
    };

    private static RuleEngine Engine(params Rule[] rules) =>
        new(new RuleSet { Version = 1, Rules = [.. rules] });

    private static Rule Prohibit(string name, Action<Rule>? configure = null)
    {
        var rule = new Rule
        {
            Name = name,
            Category = "Test",
            Reason = "Software prohibited by policy.",
            Status = ComplianceStatus.Fail,
        };

        configure?.Invoke(rule);
        return rule;
    }

    [Fact]
    public void Software_matching_no_rule_passes()
    {
        var engine = Engine(Prohibit("Adobe", r => r.Aliases = ["Photoshop"]));

        var verdict = engine.Evaluate(Installed("Blender"));

        verdict.Status.ShouldBe(ComplianceStatus.Pass);
        verdict.RuleName.ShouldBeNull();
    }

    [Theory]
    [InlineData(RuleMatchType.Contains, "Photoshop", "Adobe Photoshop 2024", true)]
    [InlineData(RuleMatchType.Contains, "Photoshop", "Blender", false)]
    [InlineData(RuleMatchType.StartsWith, "Adobe", "Adobe Photoshop", true)]
    [InlineData(RuleMatchType.StartsWith, "Photoshop", "Adobe Photoshop", false)]
    [InlineData(RuleMatchType.EndsWith, "2024", "Adobe Photoshop 2024", true)]
    [InlineData(RuleMatchType.EndsWith, "Adobe", "Adobe Photoshop", false)]
    [InlineData(RuleMatchType.Exact, "WinRAR", "WinRAR", true)]
    [InlineData(RuleMatchType.Exact, "WinRAR", "WinRAR 7.01", false)]
    [InlineData(RuleMatchType.Regex, @"^Adobe\s.*2024$", "Adobe Photoshop 2024", true)]
    [InlineData(RuleMatchType.Regex, @"^Adobe\s.*2024$", "Adobe Photoshop 2023", false)]
    public void Match_types_behave_as_documented(RuleMatchType matchType, string pattern, string name, bool expectFail)
    {
        var engine = Engine(Prohibit("rule", r =>
        {
            r.MatchType = matchType;
            r.Aliases = [pattern];
        }));

        var verdict = engine.Evaluate(Installed(name));

        verdict.Status.ShouldBe(expectFail ? ComplianceStatus.Fail : ComplianceStatus.Pass);
    }

    [Theory]
    [InlineData("photoshop")]
    [InlineData("PHOTOSHOP")]
    [InlineData("PhOtOsHoP")]
    public void Matching_ignores_case(string name)
    {
        var engine = Engine(Prohibit("Adobe", r => r.Aliases = ["Photoshop"]));

        engine.Evaluate(Installed(name)).Status.ShouldBe(ComplianceStatus.Fail);
    }

    [Fact]
    public void Publisher_alone_is_enough_to_match()
    {
        // "Everything published by Adobe" must fail products whose names the policy never lists.
        var engine = Engine(Prohibit("Adobe", r => r.Publisher = "Adobe"));

        var verdict = engine.Evaluate(Installed("Some Unlisted Tool", publisher: "Adobe Inc."));

        verdict.Status.ShouldBe(ComplianceStatus.Fail);
    }

    [Fact]
    public void Executable_patterns_support_wildcards()
    {
        var engine = Engine(Prohibit("Substance", r => r.ExecutableNames = ["Substance*.exe"]));

        engine.Evaluate(Portable("Substance 3D Painter.exe")).Status.ShouldBe(ComplianceStatus.Fail);
        engine.Evaluate(Portable("Blender.exe")).Status.ShouldBe(ComplianceStatus.Pass);
    }

    [Fact]
    public void Folder_names_match_against_the_location()
    {
        var engine = Engine(Prohibit("Tools", r => r.FolderNames = ["KMSPico"]));

        var verdict = engine.Evaluate(Installed("Unknown", location: @"C:\Windows\KMSPico\bin"));

        verdict.Status.ShouldBe(ComplianceStatus.Fail);
    }

    [Fact]
    public void Higher_priority_rule_wins()
    {
        var engine = Engine(
            Prohibit("broad", r =>
            {
                r.Aliases = ["Office"];
                r.Priority = 10;
            }),
            Prohibit("specific", r =>
            {
                r.Aliases = ["Office Compatibility Pack"];
                r.Priority = 100;
                r.Status = ComplianceStatus.Pass;
                r.Reason = "Permitted by policy.";
            }));

        var verdict = engine.Evaluate(Installed("Office Compatibility Pack"));

        verdict.Status.ShouldBe(ComplianceStatus.Pass);
        verdict.RuleName.ShouldBe("specific");
    }

    [Fact]
    public void Disabled_rules_are_ignored()
    {
        var engine = Engine(Prohibit("Adobe", r =>
        {
            r.Aliases = ["Photoshop"];
            r.Enabled = false;
        }));

        engine.Evaluate(Installed("Adobe Photoshop")).Status.ShouldBe(ComplianceStatus.Pass);
    }

    [Fact]
    public void Verdict_carries_the_rule_reason_and_category()
    {
        var engine = Engine(Prohibit("Adobe suite", r =>
        {
            r.Aliases = ["Photoshop"];
            r.Category = "Adobe";
            r.Reason = "Software prohibited by policy.";
        }));

        var verdict = engine.Evaluate(Installed("Adobe Photoshop"));

        verdict.Reason.ShouldBe("Software prohibited by policy.");
        verdict.Category.ShouldBe("Adobe");
        verdict.RuleName.ShouldBe("Adobe suite");
    }

    [Fact]
    public void Constructing_an_engine_over_an_invalid_policy_throws()
    {
        var ruleSet = new RuleSet
        {
            Version = 1,
            Rules = [new Rule { Name = "broken", Reason = string.Empty }],
        };

        Should.Throw<RuleConfigurationException>(() => new RuleEngine(ruleSet));
    }
}
