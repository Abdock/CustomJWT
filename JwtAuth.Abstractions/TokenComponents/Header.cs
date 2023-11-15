using System.Text.Json.Serialization;

namespace JwtAuth.Abstractions.TokenComponents;

public record Header
{
    [JsonPropertyName("alg")]
    public required string Algorithm { get; init; }
    [JsonPropertyName("typ")]
    public required string TokenType { get; init; }
}