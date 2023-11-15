using System.Text.Json;
using JwtAuth.Abstractions;
using JwtAuth.Abstractions.Exceptions;
using JwtAuth.Abstractions.TokenComponents;
using JwtAuth.Jwt.Helpers;

namespace JwtAuth.Jwt;

public class JwtTokenProvider : ITokenProvider
{
    private const string ValidTokenType = "JWT";

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
            TokenType = ValidTokenType
        };
        var payload = new Payload
        {
            Audience = info.Audience,
            Issuer = info.Issuer,
            Expiration = info.ExpirationDate.ToUnixTimeSeconds(),
            CustomClaims = info.CustomClaims.ToList()
        };
        var serializedHeader = JsonSerializer.Serialize(header);
        var serializedPayload = JsonSerializer.Serialize(payload);
        var encodedHeader = _componentEncoder.Encode(serializedHeader);
        var encodedPayload = _componentEncoder.Encode(serializedPayload);
        var signature = _hashingAlgorithm.ComputeHash(info.SecuredKey, $"{encodedHeader}.{encodedPayload}");
        return $"{encodedHeader}.{encodedPayload}.{signature.ConvertBase64StringToBase64UrlString()}";
    }

    public bool IsValidToken(string jwt, string securedKey)
    {
        const char tokenComponentSeparator = '.';
        var components = jwt.Split(tokenComponentSeparator);
        if (components.Length != 3)
        {
            throw new InvalidTokenException("Token should consists of 3 components: Header, Payload, Signature");
        }

        var serializedHeader = _componentEncoder.Decode(components[0]);
        var serializedPayload = _componentEncoder.Decode(components[1]);
        var header = JsonSerializer.Deserialize<Header>(serializedHeader) ?? throw new InvalidTokenException("Invalid token header");
        var payload = JsonSerializer.Deserialize<Payload>(serializedPayload) ?? throw new InvalidTokenException("Invalid token payload");
        if (!header.TokenType.Equals(ValidTokenType, StringComparison.OrdinalIgnoreCase) || !header.Algorithm.Equals(_hashingAlgorithm.AlgorithmName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var offset = DateTimeOffset.FromUnixTimeSeconds(payload.Expiration);
        if (offset.UtcDateTime < DateTimeOffset.Now.UtcDateTime)
        {
            return false;
        }

        var decodedSignature = _hashingAlgorithm.ComputeHash(securedKey, $"{components[0]}.{components[1]}").ConvertBase64StringToBase64UrlString();
        return decodedSignature.Equals(components[2]);
    }
}