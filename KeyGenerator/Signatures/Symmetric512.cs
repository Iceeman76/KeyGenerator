using System.Security.Cryptography;
using System.Text;

namespace KeyGenerator.Signatures;

public sealed record Symmetric512 : ISignature
{
    public const string AlgName = "HS512";

    string ISignature.Alg => AlgName;

    public byte[] Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA512(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);

        return hmac.ComputeHash(buffer);
    }
}
