using System.Text;
using System.Text.Json;
using DotNetLab.KeyGenerator.Signatures;

namespace DotNetLab.KeyGenerator.Tests;

public sealed class AdditionalCoverageTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private IKeyService _keyService = null!;

    [SetUp]
    public void Setup()
    {
        _keyService = TestServiceProvider.CreateKeyService();
    }

    [Test]
    public void ParseToken_ShouldFail_WhenPayloadIsTamperedButSignatureKept()
    {
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user1",
                Scopes = ["read"],
                Iat = 0,
                Exp = 9999999999
            }
        };

        var token = _keyService.CreateToken(apiKey);
        var parts = token.Split('.');

        var tamperedPayload = new ApiKey.Definition
        {
            Sub = "admin",
            Scopes = ["admin"],
            Iat = 0,
            Exp = 9999999999
        };

        var json = JsonSerializer.Serialize(tamperedPayload, JsonOptions);
        var newPayload = Base64Url.Encode(Encoding.UTF8.GetBytes(json));

        var tampered = $"{parts[0]}.{newPayload}.{parts[2]}";
        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(tampered);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid signature"));
        }
    }

    [Test]
    public void ParseToken_ShouldPreserveAllFieldsAndToken_OnRoundtrip()
    {
        var original = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user123",
                Scopes = ["read", "write", "admin"],
                Iat = 1716750000,
                Exp = 1716753600
            }
        };

        var token = _keyService.CreateToken(original);
        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Sub, Is.EqualTo("user123"));
            Assert.That(result.Value.Payload.Scopes, Is.EqualTo(["read", "write", "admin"]));
            Assert.That(result.Value.Payload.Iat, Is.EqualTo(1716750000));
            Assert.That(result.Value.Payload.Exp, Is.EqualTo(1716753600));
            Assert.That(result.Value.Token, Is.EqualTo(token));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsEmptyString()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(string.Empty);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid format"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenHasFourParts()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>("A.B.C.D");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid token format. Expected 3 parts."));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenHasSinglePart()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>("A");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid token format. Expected 3 parts."));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenHeaderIsNotValidBase64Url()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>("!!!.B.C");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.StartWith("Invalid format:"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenSignaturePartIsNotValidBase64Url()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "x" } };
        var token = _keyService.CreateToken(key);
        var parts = token.Split('.');

        var bad = $"{parts[0]}.{parts[1]}.!!!";
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(bad);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.StartWith("Invalid format:"));
        }
    }

    [Test]
    public void Base64Url_Encode_ShouldNotContainPaddingOrUnsafeChars()
    {
        for (var length = 0; length <= 10; length++)
        {
            var bytes = new byte[length];

            for (var index = 0; index < length; index++)
            {
                bytes[index] = (byte)(index * 31 + 7);
            }

            var encoded = Base64Url.Encode(bytes);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(encoded, Does.Not.Contain("="), $"length={length}");
                Assert.That(encoded, Does.Not.Contain("+"), $"length={length}");
                Assert.That(encoded, Does.Not.Contain("/"), $"length={length}");
            }
        }
    }

    [Test]
    public void Base64Url_Roundtrip_ShouldPreserveBytes()
    {
        for (var length = 0; length <= 10; length++)
        {
            var bytes = new byte[length];

            for (var index = 0; index < length; index++)
            {
                bytes[index] = (byte)(index * 17 + 3);
            }

            var encoded = Base64Url.Encode(bytes);
            var decoded = Base64Url.Decode(encoded);

            Assert.That(decoded, Is.EqualTo(bytes), $"length={length}");
        }
    }

    [Test]
    public void Verify_ShouldSucceed_WhenIatIsInFutureButExpIsAlsoInFuture()
    {
        var now = TestClock.UtcNow;
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user1",
                Scopes = ["read"],
                Iat = now.AddHours(1).ToUnixTimeSeconds(),
                Exp = now.AddHours(2).ToUnixTimeSeconds()
            }
        };

        var result = apiKey.Verify(TestClock.Provider);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void Verify_ShouldFail_WhenExpEqualsNow()
    {
        var nowSeconds = TestClock.UtcNow.ToUnixTimeSeconds();
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user1",
                Scopes = ["read"],
                Iat = nowSeconds - 10,
                Exp = nowSeconds
            }
        };

        var result = apiKey.Verify(TestClock.Provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Expired"));
        }
    }

    [Test]
    public void Verify_ShouldFail_WhenExpAndIatAreBothInPast()
    {
        var timestamp = TestClock.UtcNow.AddDays(-1).ToUnixTimeSeconds();
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user1",
                Scopes = ["read"],
                Iat = timestamp,
                Exp = timestamp
            }
        };

        var result = apiKey.Verify(TestClock.Provider);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Expired"));
        }
    }

    [Test]
    public void ParseToken_ShouldSucceed_WhenParsedByDifferentServiceInstanceWithSameSecret()
    {
        var creator = TestServiceProvider.CreateKeyService();
        var parser = TestServiceProvider.CreateKeyService();

        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "stateless-user",
                Scopes = ["read"],
                Iat = 1,
                Exp = 9999999999
            }
        };

        var token = creator.CreateToken(apiKey);
        var result = parser.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Sub, Is.EqualTo("stateless-user"));
        }
    }

    private sealed class OtherSecretConfiguration : IKeyConfiguration
    {
        public string Secret => "completely-different-secret-that-is-long-enough";
    }

    [Test]
    public void ParseToken_ShouldFail_WhenSecretDiffers()
    {
        var creator = _keyService;
        var parser = new KeyService(new OtherSecretConfiguration(), [new Symmetric64(), new Symmetric256(), new Symmetric512()]);

        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user1",
                Scopes = ["read"],
                Iat = 0,
                Exp = 9999999999
            }
        };

        var token = creator.CreateToken(apiKey);
        var result = parser.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid signature"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenAlgIsNone()
    {
        var header = new Header { Alg = "none", Typ = "API" };
        var headerJson = JsonSerializer.Serialize(header, JsonOptions);
        var headerEncoded = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));

        var payload = new ApiKey.Definition
        {
            Sub = "attacker",
            Scopes = ["admin"],
            Iat = 0,
            Exp = 9999999999
        };

        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        var payloadEncoded = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var token = $"{headerEncoded}.{payloadEncoded}.";

        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Headers mismatch"));
        }
    }

    [Test]
    public void StringKey_ShouldRoundtrip_WithUnicodePayload()
    {
        const string value = "😀 åäö ✓ 漢字 — Unicode!";
        var key = new StringKey { Payload = new StringKey.Definition { Value = value } };

        var token = _keyService.CreateToken(key);
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Value, Is.EqualTo(value));
        }
    }

    [Test]
    public void StringKey_ShouldRoundtrip_WithLargePayload()
    {
        var value = new string('x', 8 * 1024);
        var key = new StringKey { Payload = new StringKey.Definition { Value = value } };

        var token = _keyService.CreateToken(key);
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Value, Is.EqualTo(value));
        }
    }
}
