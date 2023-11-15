using System.Text;

namespace JwtAuth.Jwt.Helpers;

internal static class Base64StringConverter
{
    private const char   Base64Character62        = '+';
    private const char   Base64Character63        = '/';
    private const string Base64DoublePadCharacter = "==";
    private const char   Base64PadCharacter       = '=';
    private const char   Base64UrlCharacter62     = '-';
    private const char   Base64UrlCharacter63     = '_';

    public static string ConvertBase64StringToBase64UrlString(this string base64String)
    {
        var base64UrlStringBuilder = new StringBuilder(base64String.TrimEnd(Base64PadCharacter));
        return base64UrlStringBuilder
            .Replace(Base64Character62, Base64UrlCharacter62)
            .Replace(Base64Character63, Base64UrlCharacter63)
            .ToString();
    }
}