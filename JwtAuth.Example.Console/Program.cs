using JwtAuth.Abstractions;
using JwtAuth.Jwt;
using JwtAuth.Jwt.SecuredHashingAlgorithms;

ISecuredHashingAlgorithm hashingAlgorithm = new HmacSha256Algorithm();
ITokenProvider tokenProvider = new JwtTokenProvider(hashingAlgorithm);
var tokenInfo = new TokenInfo
{
    Audience = "localAudience",
    Issuer = "localIssuer",
    ExpirationDate = DateTimeOffset.Now.AddHours(1),
    SecuredKey = "MySuperSecuredKey"
};
var jwt = tokenProvider.GenerateJwt(tokenInfo);
Console.WriteLine(jwt);