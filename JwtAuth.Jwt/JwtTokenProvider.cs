using JwtAuth.Abstractions;
using JwtAuth.Abstractions.TokenComponents;
using JwtAuth.Jwt.Extensions;

namespace JwtAuth.Jwt;

public class JwtTokenProvider : ITokenProvider
{
    private readonly ISecuredHashingAlgorithm _hashingAlgorithm;

    public JwtTokenProvider(ISecuredHashingAlgorithm hashingAlgorithm)
    {
        _hashingAlgorithm = hashingAlgorithm;
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
        var signature = _hashingAlgorithm.ComputeHash(info.SecuredKey);
        var encodedHeader = header.ToBase64String();
        var encodedPayload = payload.ToBase64String();
        return $"{encodedHeader}.{encodedPayload}.{signature}";
    }
}