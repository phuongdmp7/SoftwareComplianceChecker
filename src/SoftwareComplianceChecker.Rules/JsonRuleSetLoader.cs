using System.Text.Json;
using System.Text.Json.Serialization;

namespace SoftwareComplianceChecker.Rules;

/// <summary>
/// Loads the compliance policy from a JSON file.
/// </summary>
public interface IRuleSetLoader
{
    /// <summary>Loads and validates a rule set.</summary>
    /// <param name="path">Path to the rules file.</param>
    /// <exception cref="RuleConfigurationException">The file is missing, malformed, or invalid.</exception>
    RuleSet Load(string path);
}

/// <summary>
/// Reads rules.json into a validated <see cref="RuleSet"/>.
/// </summary>
public sealed class JsonRuleSetLoader : IRuleSetLoader
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) },
    };

    /// <inheritdoc />
    public RuleSet Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            throw new RuleConfigurationException(
                $"The compliance policy file was not found at '{path}'. " +
                "The application cannot evaluate compliance without it.");
        }

        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new RuleConfigurationException($"The compliance policy file at '{path}' could not be read.", ex);
        }

        RuleSet? ruleSet;
        try
        {
            ruleSet = JsonSerializer.Deserialize<RuleSet>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new RuleConfigurationException(
                $"The compliance policy file at '{path}' is not valid JSON. {ex.Message}", ex);
        }

        if (ruleSet is null)
        {
            throw new RuleConfigurationException($"The compliance policy file at '{path}' is empty.");
        }

        var errors = RuleSetValidator.Validate(ruleSet);
        if (errors.Count > 0)
        {
            throw new RuleConfigurationException(
                $"The compliance policy file at '{path}' is not valid.", errors);
        }

        return ruleSet;
    }
}
