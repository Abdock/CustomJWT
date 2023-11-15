using System.Security.Cryptography;
using System.Text;
using JwtAuth.Abstractions;

namespace JwtAuth.Jwt.SecuredHashingAlgorithms;

public class HmacSha256Algorithm : ISecuredHashingAlgorithm
{
    private readonly Encoding _encoding;
    private readonly HashAlgorithm _algorithm;

    public HmacSha256Algorithm()
    {
        _encoding = Encoding.UTF8;
        _algorithm = new HMACSHA256();
    }

    public HmacSha256Algorithm(Encoding encoding) : this()
    {
        _encoding = encoding;
    }

    public HmacSha256Algorithm(Encoding encoding, byte[] key) : this(encoding)
    {
        _algorithm = new HMACSHA256(key);
    }

    public string AlgorithmName => HashingAlgorithms.HmacSha256;

    public string ComputeHash(string data)
    {
        var encodedKey = _encoding.GetBytes(data);
        var hashedData = _algorithm.ComputeHash(encodedKey);
        return Convert.ToBase64String(hashedData);
    }

    public string ComputeHash(string key, string data)
    {
        var encodedKey = _encoding.GetBytes(key);
        var encodedData = _encoding.GetBytes(data);
        var hashedData = HMACSHA256.HashData(encodedKey, encodedData);
        return Convert.ToBase64String(hashedData);
    }
}