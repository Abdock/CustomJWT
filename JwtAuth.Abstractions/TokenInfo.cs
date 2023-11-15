using System.Security.Claims;

namespace JwtAuth.Abstractions;

public record TokenInfo
{
    public required string Audience { get; init; }
    public required string Issuer { get; init; }
    public required DateTimeOffset ExpirationDate { get; init; }
    public required string SecuredKey { get; init; }
    public IEnumerable<Claim> CustomClaims { get; init; } = Enumerable.Empty<Claim>();
}