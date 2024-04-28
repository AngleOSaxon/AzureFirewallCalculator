using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.ResourceManager.Network.Models;
using OneOf;

namespace AzureFirewallCalculator.Core.PowershellSource;

public class RuleCollectionJsonConverter : JsonConverter<RuleCollection>
{
    private readonly static byte[] RulesPropertyBytes = Encoding.UTF8.GetBytes("Rules");
    private readonly static byte[] RuleTypePropertyBytes = Encoding.UTF8.GetBytes("RuleType");
    public override RuleCollection? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var originalPosition = reader;

        OneOf<NetworkRule[], ApplicationRule[]> rules = Array.Empty<NetworkRule>();
        var startDepth = reader.CurrentDepth;
        // Read into the object until we find the type of the rules
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals(RulesPropertyBytes))
                {
                    // Copy the reader to preserve the original position, so we can use it to read the whole array once we know its type
                    var forwardReader = reader;
                    while (forwardReader.Read())
                    {
                        // Read until we find the first RuleType param
                        // WARNING: This is case-sensitive
                        if (forwardReader.TokenType == JsonTokenType.PropertyName && forwardReader.ValueTextEquals(RuleTypePropertyBytes))
                        {
                            forwardReader.Read();
                            var type = forwardReader.GetString();
                            // Deserialize as the appropriate rule type, using the saved rule position
                            if (type == "ApplicationRule")
                            {
                                rules = JsonSerializer.Deserialize<ApplicationRule[]>(ref reader, options) ?? throw new ArgumentException($"Failed to deserialize {nameof(ApplicationRule)}");
                            }
                            else if (type == "NetworkRule")
                            {
                                rules = JsonSerializer.Deserialize<NetworkRule[]>(ref reader, options) ?? throw new ArgumentException($"Failed to deserialize {nameof(NetworkRule)}");
                            }
                            else
                            {
                                throw new ArgumentException($"Unknown RuleType value. Expected 'Network' or 'Application'; received '{type}'");
                            }
                            // Stop processing; we have what we came for
                            break;
                        }
                    }
                }
            }
            // Ensure we read to the end of the original object; otherwise JsonSerializer throws an exception
            if (reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == startDepth)
            {
                break;
            }
        }

        // Having found the rule type, we want to deserialize the rest of the RuleCollection
        var duplicateOptions = new JsonSerializerOptions(options);
        // Preserve existing options, but remove this converter to avoid recursion
        duplicateOptions.Converters.Remove(this);
        // The Rules property is marked with [JsonIgnore], so it will simply get a default value
        var collection = JsonSerializer.Deserialize<RuleCollection>(ref originalPosition, duplicateOptions) ?? throw new ArgumentException($"Unable to deserialize {nameof(RuleCollection)}");
        // Clone the deserialized copy and add in the rules.  Wouldn't need the duplication if it wasn't a record type, but I don't feel like changing it
        return collection with { Rules = rules };
    }

    public override void Write(Utf8JsonWriter writer, RuleCollection value, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }
}