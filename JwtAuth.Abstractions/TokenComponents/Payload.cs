using System.Security.Claims;
using System.Text.Json.Serialization;

namespace JwtAuth.Abstractions.TokenComponents;

public record Payload
{
    [JsonPropertyName("aud")]
    public required string Audience { get; init; }
    [JsonPropertyName("iss")]
    public required string Issuer { get; init; }
    [JsonPropertyName("iat")]
    public required long Expiration { get; init; }
    [JsonIgnore]
    public IReadOnlyCollection<Claim>? CustomClaims { get; init; }
}