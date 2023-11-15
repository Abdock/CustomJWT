using System.Text;
using JwtAuth.Abstractions;

namespace JwtAuth.Jwt.Encoders;

public class Base64UrlTokenComponentEncoder : ITokenComponentEncoder
{
    private const char   Base64Character62        = '+';
    private const char   Base64Character63        = '/';
    private const string Base64DoublePadCharacter = "==";
    private const char   Base64PadCharacter       = '=';
    private const char   Base64UrlCharacter62     = '-';
    private const char   Base64UrlCharacter63     = '_';

    private readonly Encoding _encoding;

    public Base64UrlTokenComponentEncoder()
    {
        _encoding = Encoding.UTF8;
    }

    public Base64UrlTokenComponentEncoder(Encoding encoding)
    {
        _encoding = encoding;
    }

    public string Encode(string data)
    {
        var encodedData = _encoding.GetBytes(data);
        var base64String = Convert.ToBase64String(encodedData);
        var base64UrlStringBuilder = new StringBuilder(base64String.Split(Base64PadCharacter).First());
        return base64UrlStringBuilder
            .Replace(Base64Character62, Base64UrlCharacter62)
            .Replace(Base64Character63, Base64UrlCharacter63)
            .ToString();
    }

    public string Decode(string base64UrlStringEncoded)
    {
        var initialStringBuilder = new StringBuilder(base64UrlStringEncoded);
        initialStringBuilder = initialStringBuilder
            .Replace(Base64UrlCharacter62, Base64Character62)
            .Replace(Base64UrlCharacter63, Base64Character63);

        switch (base64UrlStringEncoded.Length % 4)
        {
            case 0:
                break;
            case 2:
                initialStringBuilder.Append(Base64DoublePadCharacter);
                break;
            case 3:
                initialStringBuilder.Append(Base64PadCharacter);
                break;
            default:
                throw new FormatException("Invalid Base64 URL encoding.");
        }

        var initialString = Convert.FromBase64String(initialStringBuilder.ToString());
        return _encoding.GetString(initialString);
    }
}