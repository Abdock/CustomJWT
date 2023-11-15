namespace JwtAuth.Abstractions;

public interface ITokenProvider
{
    string GenerateJwt(TokenInfo info);
}