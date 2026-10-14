using System.Text;
using System.Text.Json;

namespace KeyGenerator.Tests;

public sealed class TokenStructureTests
{
    private IKeyService _keyService = null!;

    [SetUp]
    public void Setup()
    {
        _keyService = TestServiceProvider.CreateKeyService();
    }

    [Test]
    public void ApiKey_ShouldUseExpectedTokenStructure()
    {
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user-123",
                Scopes = ["read", "write"],
                Iat = 1716750000,
                Exp = 1716753600
            }
        };

        var token = _keyService.CreateToken(apiKey);
        var parts = token.Split('.');

        using (Assert.EnterMultipleScope())
        {
            Assert.That(parts, Has.Length.EqualTo(3));

            var headerJson = Encoding.UTF8.GetString(DecodeBase64Url(parts[0]));
            using var header = JsonDocument.Parse(headerJson);
            
            Assert.That(header.RootElement.GetProperty("alg").GetString(), Is.EqualTo("HS256"));
            Assert.That(header.RootElement.GetProperty("typ").GetString(), Is.EqualTo("API"));

            var payloadJson = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));
            using var payload = JsonDocument.Parse(payloadJson);

            Assert.That(payload.RootElement.GetProperty("sub").GetString(), Is.EqualTo("user-123"));
            Assert.That(payload.RootElement.GetProperty("iat").GetInt64(), Is.EqualTo(1716750000));
            Assert.That(payload.RootElement.GetProperty("exp").GetInt64(), Is.EqualTo(1716753600));
            
            Assert.That(parts[0], Does.Not.Contain("="));
            Assert.That(parts[1], Does.Not.Contain("="));
            Assert.That(parts[2], Does.Not.Contain("="));
        }
    }

    [Test]
    public void StringKey_ShouldUseExpectedTokenStructure()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "test-payload" } };

        var token = _keyService.CreateToken(key);
        var parts = token.Split('.');

        using (Assert.EnterMultipleScope())
        {
            Assert.That(parts, Has.Length.EqualTo(3));

            var headerJson = Encoding.UTF8.GetString(DecodeBase64Url(parts[0]));
            using var header = JsonDocument.Parse(headerJson);

            Assert.That(header.RootElement.GetProperty("alg").GetString(), Is.EqualTo("HS256"));
            Assert.That(header.RootElement.GetProperty("typ").GetString(), Is.EqualTo("STRING"));

            var payloadJson = Encoding.UTF8.GetString(DecodeBase64Url(parts[1]));
            using var payload = JsonDocument.Parse(payloadJson);

            Assert.That(payload.RootElement.GetProperty("value").GetString(), Is.EqualTo("test-payload"));

            Assert.That(parts[0], Does.Not.Contain("="));
            Assert.That(parts[1], Does.Not.Contain("="));
            Assert.That(parts[2], Does.Not.Contain("="));
        }
    }

    private static byte[] DecodeBase64Url(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }

        return Convert.FromBase64String(base64);
    }
}
