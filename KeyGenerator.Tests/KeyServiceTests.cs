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
}
