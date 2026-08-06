using Shouldly;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Rules;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// Exercises the policy that actually ships, against realistic software names.
/// </summary>
/// <remarks>
/// The rule engine's own tests prove the matching machinery works. These prove the shipped
/// <c>config/rules.json</c> classifies real products the way it is meant to, which is a
/// different and easily broken thing: a pattern that is too broad silently passes or fails
/// software nobody intended it to touch, and nothing else would catch it.
/// </remarks>
public sealed class ShippedPolicyTests
{
    private static RuleEngine? TryLoadShippedEngine()
    {
        var path = RepositoryFiles.RulesJson();

        return path is null ? null : new RuleEngine(new JsonRuleSetLoader().Load(path));
    }

    private static SoftwareItem Installed(string name, string? publisher = null) => new()
    {
        DisplayName = name,
        Publisher = publisher,
        Source = SoftwareSource.Installed,
    };

    [Theory]
    // Prohibited by policy.
    [InlineData("Adobe Photoshop 2024", "Adobe Inc.", ComplianceStatus.Fail)]
    [InlineData("Adobe Substance 3D Painter", "Adobe Inc.", ComplianceStatus.Fail)]
    [InlineData("JetBrains Rider 2025.1", "JetBrains s.r.o.", ComplianceStatus.Fail)]
    [InlineData("Autodesk Maya 2026", "Autodesk", ComplianceStatus.Fail)]
    [InlineData("Marmoset Toolbag 5", "Marmoset LLC", ComplianceStatus.Fail)]
    [InlineData("Microsoft 365 Apps for enterprise", "Microsoft Corporation", ComplianceStatus.Fail)]
    [InlineData("WinRAR 7.01 (64-bit)", "win.rar GmbH", ComplianceStatus.Fail)]
    [InlineData("KMSPico", null, ComplianceStatus.Fail)]

    // Permitted, or unlisted and therefore permitted by default.
    [InlineData("Blender", "Blender Foundation", ComplianceStatus.Pass)]
    [InlineData("Unity Hub", "Unity Technologies ApS", ComplianceStatus.Pass)]
    [InlineData("Visual Studio Code", "Microsoft Corporation", ComplianceStatus.Pass)]
    [InlineData("Godot Engine", null, ComplianceStatus.Pass)]
    [InlineData("7-Zip 24.08", "Igor Pavlov", ComplianceStatus.Pass)]
    [InlineData("Some Unlisted Internal Tool", "Contoso", ComplianceStatus.Pass)]
    public void The_shipped_policy_classifies_software_as_intended(
        string name, string? publisher, ComplianceStatus expected)
    {
        var engine = TryLoadShippedEngine();

        if (engine is null)
        {
            return;
        }

        engine.Evaluate(Installed(name, publisher)).Status.ShouldBe(expected);
    }

    [Theory]
    [InlineData("Fork")]
    [InlineData("Fork 2.4.1")]
    public void Fork_is_prohibited(string name)
    {
        // Fork is free only for evaluation; using it for commercial work requires a purchased
        // licence, which puts it in the same category as WinRAR rather than with the free tools.
        var engine = TryLoadShippedEngine();

        if (engine is null)
        {
            return;
        }

        engine.Evaluate(Installed(name)).Status.ShouldBe(ComplianceStatus.Fail);
    }

    [Theory]
    [InlineData("ForkLift")]
    [InlineData("Forklift Simulator")]
    public void The_fork_rule_does_not_catch_unrelated_software(string name)
    {
        // The rule is anchored precisely because "Fork" as a substring would fail any product
        // whose name merely contains it.
        var engine = TryLoadShippedEngine();

        if (engine is null)
        {
            return;
        }

        engine.Evaluate(Installed(name)).Status.ShouldBe(ComplianceStatus.Pass);
    }

    [Fact]
    public void Every_prohibited_rule_explains_itself()
    {
        var path = RepositoryFiles.RulesJson();

        if (path is null)
        {
            return;
        }

        var ruleSet = new JsonRuleSetLoader().Load(path);

        // A FAIL a user cannot act on is not a useful finding.
        foreach (var rule in ruleSet.Rules.Where(r => r.Status == ComplianceStatus.Fail))
        {
            rule.Reason.ShouldNotBeNullOrWhiteSpace();
        }
    }
}
