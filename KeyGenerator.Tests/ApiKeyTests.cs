namespace KeyGenerator.Tests;

public sealed class ApiKeyTests
{
    private IKeyService _keyService = null!;

    [SetUp]
    public void Setup()
    {
        _keyService = TestServiceProvider.CreateKeyService();
    }

    [Test]
    public void Create_ShouldGenerateValidToken()
    {
        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user123",
                Scopes = ["read"],
                Iat = TestClock.UtcNow.ToUnixTimeSeconds(),
                Exp = TestClock.UtcNow.AddHours(1).ToUnixTimeSeconds()
            }
        };

        var token = _keyService.CreateToken(apiKey);

        Assert.That(token, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public void Parse_ShouldReturnValidApiKey()
    {
        var original = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user123",
                Scopes = ["read"],
                Iat = TestClock.UtcNow.ToUnixTimeSeconds(),
                Exp = TestClock.UtcNow.AddHours(1).ToUnixTimeSeconds()
            }
        };

        var token = _keyService.CreateToken(original);
        var result = _keyService.ParseToken<ApiKey, ApiKey.Definition>(token);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Value.Payload.Sub, Is.EqualTo("user123"));
        }
    }

    [Test]
    public void Verify_ShouldFail_WhenExpired()
    {
        var now = TestClock.UtcNow;
        var expiredTime = now.AddHours(-1);

        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user123",
                Scopes = ["read"],
                Iat = expiredTime.AddHours(-1).ToUnixTimeSeconds(),
                Exp = expiredTime.ToUnixTimeSeconds()
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
    public void Verify_ShouldSucceed_WhenNotExpired()
    {
        var now = TestClock.UtcNow;
        var validTime = now.AddHours(1);

        var apiKey = new ApiKey
        {
            Payload = new ApiKey.Definition
            {
                Sub = "user123",
                Scopes = ["read"],
                Iat = now.ToUnixTimeSeconds(),
                Exp = validTime.ToUnixTimeSeconds()
            }
        };

        var result = apiKey.Verify(TestClock.Provider);

        Assert.That(result.IsSuccess, Is.True);
    }
}
