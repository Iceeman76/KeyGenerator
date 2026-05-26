namespace KeyGenerator.Tests;

[TestFixture]
public class KeyGeneratorTests
{
    [Test]
    public void TestApiKey()
    {
        var key = ApiKey.Create("benny", ["read", "write"]);
        Console.WriteLine($"Generated token: {key.Token}");
        Console.WriteLine($"Token length: {key.Token.Length}");

        var result = ApiKey.Parse(key.Token);
        if (result.IsFailure) Console.WriteLine(result.Problem);

        if (result.IsSuccess)
        {
            var parsed = result.Value!;
            var iat = DateTimeOffset.FromUnixTimeSeconds(parsed.Payload.Iat).ToLocalTime();
            var exp = DateTimeOffset.FromUnixTimeSeconds(parsed.Payload.Exp).ToLocalTime();

            Console.WriteLine($"Header: {parsed.Header}");
            Console.WriteLine($"Verified: {parsed.Verify()}");
            Console.WriteLine($"User ID: {parsed.Payload.Uid}");
            Console.WriteLine($"IAT: {iat}");
            Console.WriteLine($"EXP: {exp}");

            Console.WriteLine($"Scopes: {string.Join(", ", parsed.Payload.Scopes)}");
        }
    }

    [Test]
    public void TestStringKey()
    {
        var key = StringKey.Create("This is the license key");
        Console.WriteLine($"Generated token: {key.Token}");
        Console.WriteLine($"Token length: {key.Token.Length}");

        var result = StringKey.Parse(key.Token);
        if (result.IsFailure) Console.WriteLine(result.Problem);

        if (result.IsSuccess)
        {
            var parsed = result.Value!;

            Console.WriteLine($"Header: {parsed.Header}");
            Console.WriteLine($"Verified: {parsed.Verify()}");
            Console.WriteLine($"Value: {parsed.Payload}");
        }
    }
}
