using System.Security.Cryptography;
using System.Text;

namespace KeyGenerator;

public interface ISignature
{
    public int Length { get; }
    public string Generate(string input, string secret);
}

public static class Signatures
{
    public static ISignature Symmetric64 => new Symmetric64();
    public static ISignature Symmetric256 => new Symmetric256();
    public static ISignature Symmetric512 => new Symmetric512();
}

public record Symmetric64 : ISignature
{
    public const string Alg = "HS64";
    public int Length => 16;

    public string Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);
        var hash = hmac.ComputeHash(buffer);
        var truncated = hash.Take(8).ToArray();
        var signature = Convert.ToHexStringLower(truncated);

        return signature;
    }
}

public record Symmetric256 : ISignature
{
    public const string Alg = "HS256";
    public int Length => 64;

    public string Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA256(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);
        var hash = hmac.ComputeHash(buffer);
        var signature = Convert.ToHexStringLower(hash);

        return signature;
    }
}

public record Symmetric512 : ISignature
{
    public const string Alg = "HS512";
    public int Length => 128;

    public string Generate(string input, string secret)
    {
        var bytes = Encoding.UTF8.GetBytes(secret);
        using var hmac = new HMACSHA512(bytes);

        var buffer = Encoding.UTF8.GetBytes(input);
        var hash = hmac.ComputeHash(buffer);
        var signature = Convert.ToHexStringLower(hash);

        return signature;
    }
}
