namespace KeyGenerator.Tests;

public sealed class KeyServiceTests
{
    private IKeyService _keyService = null!;

    [SetUp]
    public void Setup()
    {
        _keyService = TestServiceProvider.CreateKeyService();
    }

    [Test]
    public void ParseToken_ShouldFail_WhenSignatureIsInvalid()
    {
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Uid = "user1",
                Scopes = ["admin"],
                Iat = 100,
                Exp = 200
            }
        };

        var token = _keyService.CreateToken(apiKey);
        var tamperedToken = token[..^1] + (token[^1] == 'a' ? 'b' : 'a');

        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(tamperedToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid signature"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenHeaderIsTampered()
    {
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Uid = "user1",
                Scopes = ["admin"],
                Iat = 100,
                Exp = 200
            }
        };

        var token = _keyService.CreateToken(apiKey);
        var tamperedToken = token[..4] + "ey..." + token[10..];

        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(tamperedToken);

        Assert.That(result.IsSuccess, Is.False);
    }

    [Test]
    public void StringKey_ShouldWork()
    {
        var key = new StringKey { Payload = "Hello World" };
        var token = _keyService.CreateToken(key);
        var result = _keyService.ParseToken<StringKey, string>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload, Is.EqualTo("Hello World"));
        }
    }

    [Test]
    public void CustomKey_Symmetric512_ShouldWork()
    {
        var key = new CustomKey { Payload = "Secret Data" };
        var token = _keyService.CreateToken(key);
        var result = _keyService.ParseToken<CustomKey, string>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload, Is.EqualTo("Secret Data"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenHeadersMismatch()
    {
        var key = new StringKey { Payload = "Hello World" };
        var token = _keyService.CreateToken(key);

        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Headers mismatch"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsMissingSignature()
    {
        var key = new StringKey { Payload = "test" };
        var token = _keyService.CreateToken(key);

        var headerLenHex = token[..4];
        var headerLen = int.Parse(headerLenHex, System.Globalization.NumberStyles.HexNumber);

        var truncatedToken = token[..(4 + headerLen + 1)];

        var result = _keyService.ParseToken<StringKey, string>(truncatedToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Token is too short"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsTooShort()
    {
        var result = _keyService.ParseToken<StringKey, string>("ABC");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Token too short for header"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenPayloadIsMalformed()
    {
        var key = new StringKey { Payload = "test" };
        var token = _keyService.CreateToken(key);

        var headerLenHex = token[..4];
        var headerLen = int.Parse(headerLenHex, System.Globalization.NumberStyles.HexNumber);

        var headerPart = token[..(4 + headerLen)];
        var invalidPayload = Convert.ToBase64String("invalid"u8.ToArray()).TrimEnd('=');

        var newDataToSign = headerPart + invalidPayload;
        var signature = new Symmetric64().Generate(newDataToSign, new TestConfiguration().Secret);

        var tamperedToken = newDataToSign + signature;

        var result = _keyService.ParseToken<StringKey, string>(tamperedToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Malformed json"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenAlgorithmIsNotSupported()
    {
        var signatures = new ISignature[] { new Symmetric64() };
        var service = new KeyService(new TestConfiguration(), signatures);

        var apiKey = new ApiKey { Payload = new ApiKey.Definition { Uid = "1", Iat = 0, Exp = 0, Scopes = [] } };
        var token = _keyService.CreateToken(apiKey);

        var result = service.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Algorithm HS256 is not supported"));
        }
    }

    [Test]
    public void CreateToken_ShouldThrow_WhenAlgorithmIsNotFound()
    {
        var signatures = new ISignature[] { new Symmetric64() };
        var service = new KeyService(new TestConfiguration(), signatures);
        var key = new ApiKey { Payload = new ApiKey.Definition { Uid = "1", Iat = 0, Exp = 0, Scopes = [] } };

        Assert.That(() => service.CreateToken(key), Throws.TypeOf<NotSupportedException>());
    }

    [Test]
    public void StringKey_Verify_ShouldAlwaysReturnSuccess()
    {
        var key = new StringKey { Payload = "test" };
        var result = key.Verify(TimeProvider.System);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void ParseToken_ShouldFail_WhenHeaderLengthIsNotHex()
    {
        var result = _keyService.ParseToken<StringKey, string>("GGGGsomecontent");

        Assert.That(result.IsSuccess, Is.False);
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsNull()
    {
        var result = _keyService.ParseToken<StringKey, string>(null!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Invalid format"));
        }
    }
}
