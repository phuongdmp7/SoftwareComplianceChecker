using Shouldly;
using SoftwareComplianceChecker.Core.Models;
using SoftwareComplianceChecker.Rules;
using Xunit;

namespace SoftwareComplianceChecker.Tests;

/// <summary>
/// A broken policy file must fail loudly. If it were tolerated, the application would report
/// PASS for everything, which is the most dangerous possible failure for a compliance tool.
/// </summary>
public sealed class RuleSetLoadingTests : IDisposable
{
    private readonly string directory =
        Path.Combine(Path.GetTempPath(), "scc-tests-" + Guid.NewGuid().ToString("N"));

    public RuleSetLoadingTests() => Directory.CreateDirectory(this.directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(this.directory, recursive: true);
        }
        catch (IOException)
        {
            // Temp cleanup failure must not fail the test run.
        }
    }

    private string WriteFile(string content)
    {
        var path = Path.Combine(this.directory, "rules.json");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void A_missing_policy_file_throws()
    {
        var loader = new JsonRuleSetLoader();

        Should.Throw<RuleConfigurationException>(
            () => loader.Load(Path.Combine(this.directory, "does-not-exist.json")));
    }

    [Fact]
    public void Malformed_json_throws_rather_than_yielding_an_empty_policy()
    {
        var path = this.WriteFile("{ this is not json ");

        Should.Throw<RuleConfigurationException>(() => new JsonRuleSetLoader().Load(path));
    }

    [Fact]
    public void A_valid_policy_loads_with_its_rules()
    {
        var path = this.WriteFile("""
            {
              "version": 1,
              "rules": [
                {
                  "name": "Adobe",
                  "category": "Adobe",
                  "matchType": "Contains",
                  "publisher": "Adobe",
                  "aliases": [ "Photoshop" ],
                  "priority": 100,
                  "status": "Fail",
                  "reason": "Software prohibited by policy."
                }
              ]
            }
            """);

        var ruleSet = new JsonRuleSetLoader().Load(path);

        ruleSet.Rules.Count.ShouldBe(1);
        ruleSet.Rules[0].Status.ShouldBe(ComplianceStatus.Fail);
        ruleSet.Rules[0].MatchType.ShouldBe(RuleMatchType.Contains);
        ruleSet.Rules[0].Aliases.ShouldContain("Photoshop");
    }

    [Fact]
    public void A_rule_with_no_criteria_is_rejected()
    {
        // Such a rule can never match, so its presence means the author expected protection
        // that does not exist.
        var errors = RuleSetValidator.Validate(new RuleSet
        {
            Rules = [new Rule { Name = "empty", Reason = "Prohibited." }],
        });

        errors.ShouldContain(e => e.Contains("no criteria", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void A_rule_with_no_reason_is_rejected()
    {
        var errors = RuleSetValidator.Validate(new RuleSet
        {
            Rules = [new Rule { Name = "nameless", Aliases = ["X"], Reason = string.Empty }],
        });

        errors.ShouldContain(e => e.Contains("no reason", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Duplicate_rule_names_are_rejected()
    {
        var errors = RuleSetValidator.Validate(new RuleSet
        {
            Rules =
            [
                new Rule { Name = "dup", Aliases = ["A"], Reason = "Prohibited." },
                new Rule { Name = "dup", Aliases = ["B"], Reason = "Prohibited." },
            ],
        });

        errors.ShouldContain(e => e.Contains("Duplicate rule name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void An_invalid_regular_expression_is_rejected_at_load_time()
    {
        var errors = RuleSetValidator.Validate(new RuleSet
        {
            Rules =
            [
                new Rule
                {
                    Name = "bad regex",
                    MatchType = RuleMatchType.Regex,
                    Aliases = ["([unclosed"],
                    Reason = "Prohibited.",
                },
            ],
        });

        errors.ShouldContain(e => e.Contains("invalid regular expression", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void All_problems_are_reported_together()
    {
        var errors = RuleSetValidator.Validate(new RuleSet
        {
            Rules =
            [
                new Rule { Name = string.Empty, Reason = string.Empty },
                new Rule { Name = "second", Reason = string.Empty },
            ],
        });

        // Fixing rules.json one error per run would be tedious; the validator reports the lot.
        errors.Count.ShouldBeGreaterThan(2);
    }

    [Fact]
    public void The_shipped_policy_file_is_valid()
    {
        // Guards against a typo in the default rules.json reaching a release.
        var path = LocateShippedRules();

        if (path is null)
        {
            return;
        }

        var ruleSet = new JsonRuleSetLoader().Load(path);

        ruleSet.Rules.ShouldNotBeEmpty();
        ruleSet.Rules.ShouldContain(r =>
            string.Equals(r.Category, PolicyCategories.ActivationTool, StringComparison.OrdinalIgnoreCase));
    }

    private static string? LocateShippedRules()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "config", "rules.json");

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
