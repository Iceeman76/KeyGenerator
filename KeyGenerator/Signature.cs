using System.Security.Cryptography;
using System.Text;

namespace KeyGenerator;

public interface ISignature
{
    public byte[] Generate(string input, string secret);
}

public static class Signatures
{
    public static ISignature Symmetric64 => new Symmetric64();
    public static ISignature Symmetric256 => new Symmetric256();
    public static ISignature Symmetric512 => new Symmetric512();
}

public sealed record Symmetric64 : ISignature
{
    public const string Alg = "HS64";

    public byte[] Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);
        var hash = hmac.ComputeHash(buffer);

        return hash.Take(8).ToArray();
    }
}

public sealed record Symmetric256 : ISignature
{
    public const string Alg = "HS256";

    public byte[] Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);

        return hmac.ComputeHash(buffer);
    }
}

public sealed record Symmetric512 : ISignature
{
    public const string Alg = "HS512";

    public byte[] Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA512(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);

        return hmac.ComputeHash(buffer);
    }
}
