using System.Text.Json;
using JwtAuth.Abstractions;
using JwtAuth.Abstractions.TokenComponents;

namespace JwtAuth.Jwt;

public class JwtTokenProvider : ITokenProvider
{
    private readonly ISecuredHashingAlgorithm _hashingAlgorithm;
    private readonly ITokenComponentEncoder _componentEncoder;

    public JwtTokenProvider(ISecuredHashingAlgorithm hashingAlgorithm, ITokenComponentEncoder componentEncoder)
    {
        _hashingAlgorithm = hashingAlgorithm;
        _componentEncoder = componentEncoder;
    }

    public string GenerateJwt(TokenInfo info)
    {
        var header = new Header
        {
            Algorithm = _hashingAlgorithm.AlgorithmName,
            TokenType = "JWT"
        };
        var payload = new Payload
        {
            Audience = info.Audience,
            Issuer = info.Issuer,
            Expiration = info.ExpirationDate.UtcDateTime.Ticks,
            CustomClaims = info.CustomClaims.ToList()
        };
        var serializedHeader = JsonSerializer.Serialize(header);
        var serializedPayload = JsonSerializer.Serialize(payload);
        var encodedHeader = _componentEncoder.Encode(serializedHeader);
        var encodedPayload = _componentEncoder.Encode(serializedPayload);
        var signature = _hashingAlgorithm.ComputeHash($"{serializedHeader}.{serializedPayload}", info.SecuredKey);
        return $"{encodedHeader}.{encodedPayload}.{signature}";
    }
}