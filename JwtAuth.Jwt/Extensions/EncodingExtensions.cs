using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using JwtAuth.Abstractions.TokenComponents;

namespace JwtAuth.Jwt.Extensions;

internal static class EncodingExtensions
{
    public static string ToBase64String(this Header header)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(header);
        return Convert.ToBase64String(data);
    }
    
    public static string ToBase64String(this Payload payload)
    {
        var element = JsonSerializer.SerializeToElement(payload);
        var data = JsonObject.Create(element);
        if (data is null)
        {
            throw new JsonException("Payload in invalid format");
        }

        if (payload.CustomClaims is not null)
        {
            foreach (var claim in payload.CustomClaims)
            {
                data.Add(claim.Type, claim.Value);
            }
        }

        var json = data.ToJsonString();
        var encodedJson = Encoding.UTF8.GetBytes(json);
        return Convert.ToBase64String(encodedJson);
    }
}