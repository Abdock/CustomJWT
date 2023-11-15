namespace JwtAuth.Abstractions;

public interface ITokenProvider
{
    string GenerateJwt(TokenInfo info);
    bool IsValidToken(string jwt, string securedKey);
}