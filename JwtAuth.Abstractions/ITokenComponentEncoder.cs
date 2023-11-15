namespace JwtAuth.Abstractions;

public interface ITokenComponentEncoder
{
    string Encode(string data);
    string Decode(string base64UrlStringEncoded);
}