using System.Security.Cryptography;
using System.Text;

namespace KeyGenerator.Signatures;

public sealed record Symmetric64 : ISignature
{
    public const string AlgName = "HS64";

    string ISignature.Alg => AlgName;

    public byte[] Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);
        var hash = hmac.ComputeHash(buffer);

        return hash.Take(8).ToArray();
    }
}
