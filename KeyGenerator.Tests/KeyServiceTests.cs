using DotNetLab.KeyGenerator.Signatures;

namespace DotNetLab.KeyGenerator.Tests;

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
                Sub = "user1",
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
    public void StringKey_ShouldWork()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "Hello World" } };
        var token = _keyService.CreateToken(key);
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Value, Is.EqualTo("Hello World"));
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
        var key = new StringKey { Payload = new StringKey.Definition { Value = "Hello World" } };
        var token = _keyService.CreateToken(key);

        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Headers mismatch"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsTooShort()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>("A.B");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid token format. Expected 3 parts."));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenPayloadIsMalformed()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "test" } };
        var token = _keyService.CreateToken(key);

        var parts = token.Split('.');
        var invalidPayload = Convert.ToBase64String("invalid"u8.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var tamperedToken = $"{parts[0]}.{invalidPayload}.{parts[2]}";

        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(tamperedToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Invalid signature"));
        }
    }

    [Test]
    public void ParseToken_ShouldThrow_WhenAlgorithmIsNotSupported()
    {
        var signatures = new ISignature[] { new Symmetric64() };
        var service = new KeyService(new TestConfiguration(), signatures);

        var apiKey = new ApiKey { Payload = new ApiKey.Definition { Sub = "1", Iat = 0, Exp = 0, Scopes = [] } };
        var token = _keyService.CreateToken(apiKey);

        Assert.That(() => service.ParseToken<ApiKey, ApiKey.Definition>(token), Throws.TypeOf<NotSupportedException>().With.Message.EqualTo("Algorithm HS256 is not supported"));
    }

    [Test]
    public void CreateToken_ShouldThrow_WhenAlgorithmIsNotFound()
    {
        var signatures = new ISignature[] { new Symmetric64() };
        var service = new KeyService(new TestConfiguration(), signatures);
        var key = new ApiKey { Payload = new ApiKey.Definition { Sub = "1", Iat = 0, Exp = 0, Scopes = [] } };

        Assert.That(() => service.CreateToken(key), Throws.TypeOf<NotSupportedException>());
    }

    [Test]
    public void StringKey_Verify_ShouldAlwaysReturnSuccess()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "test" } };
        var result = key.Verify(TimeProvider.System);

        Assert.That(result.IsSuccess, Is.True);
    }

    [Test]
    public void ParseToken_ShouldFail_WhenHeaderIsMalformedJson()
    {
        var malformedHeader = Convert.ToBase64String("{ \"alg\": \"HS256\""u8.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var token = $"{malformedHeader}.B.C";

        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Malformed json"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenPayloadIsMalformedJson()
    {
        var key = new StringKey { Payload = new StringKey.Definition { Value = "test" } };
        var token = _keyService.CreateToken(key);
        var parts = token.Split('.');
        var malformedPayload = Convert.ToBase64String("{ \"invalid\": "u8.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var dataToSign = $"{parts[0]}.{malformedPayload}";
        var signatureAlgorithm = new Symmetric256();
        var signatureBytes = signatureAlgorithm.Generate(dataToSign, new TestConfiguration().Secret);
        var signatureEncoded = Convert.ToBase64String(signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var tamperedToken = $"{dataToSign}.{signatureEncoded}";

        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(tamperedToken);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Is.EqualTo("Malformed json"));
        }
    }

    [Test]
    public void ParseToken_ShouldFail_WhenTokenIsNull()
    {
        var result = _keyService.ParseToken<StringKey, StringKey.Definition>(null!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Problem, Does.Contain("Invalid format"));
        }
    }
}
