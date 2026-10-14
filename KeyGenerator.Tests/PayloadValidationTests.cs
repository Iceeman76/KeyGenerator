using System.Text;
using KeyGenerator.Signatures;

namespace KeyGenerator.Tests;

public sealed class PayloadValidationTests
{
    [TestCase("null")]
    [TestCase("{}")]
    [TestCase("{\"sub\":null,\"iat\":0,\"exp\":9999999999,\"scopes\":[]}")]
    [TestCase("{\"sub\":\"user\",\"iat\":0,\"exp\":9999999999,\"scopes\":null}")]
    [TestCase("{\"sub\":\"user\",\"iat\":0,\"scopes\":[]}")]
    public void ParseToken_ShouldRejectInvalidApiPayload(string payloadJson)
    {
        var token = CreateSignedToken("API", payloadJson);
        var service = TestServiceProvider.CreateKeyService();
        var result = service.ParseToken<ApiKey, ApiKey.Definition>(token);

        Assert.That(result.IsSuccess, Is.False);
    }

    [TestCase("null")]
    [TestCase("{}")]
    [TestCase("{\"value\":null}")]
    public void ParseToken_ShouldRejectInvalidStringPayload(string payloadJson)
    {
        var token = CreateSignedToken("STRING", payloadJson);
        var service = TestServiceProvider.CreateKeyService();
        var result = service.ParseToken<StringKey, StringKey.Definition>(token);

        Assert.That(result.IsSuccess, Is.False);
    }

    [Test]
    public void CreateToken_ShouldRejectNullPayload()
    {
        var service = TestServiceProvider.CreateKeyService();
        var key = new ApiKey();

        Assert.That(() => service.CreateToken(key), Throws.ArgumentException);
    }

    [Test]
    public void ParseToken_ShouldLeaveExpiryValidationToVerify()
    {
        var service = TestServiceProvider.CreateKeyService();
        var key = new ApiKey { Payload = new ApiKey.Definition { Sub = "user", Iat = 0, Exp = 1, Scopes = [] } };
        var result = service.ParseToken<ApiKey, ApiKey.Definition>(service.CreateToken(key));

        Assert.That(result.IsSuccess, Is.True);
        Assert.That(result.Value.Verify(TestClock.Provider).IsSuccess, Is.False);
    }

    [Test]
    public void ParseToken_ShouldPropagateSignatureImplementationErrors()
    {
        var token = CreateSignedToken("API", "{\"sub\":\"user\",\"iat\":0,\"exp\":9999999999,\"scopes\":[]}");
        var service = new KeyService(new TestConfiguration(), [new BrokenSignature()]);

        Assert.That(() => service.ParseToken<ApiKey, ApiKey.Definition>(token), Throws.InvalidOperationException.With.Message.EqualTo("Signature implementation failed"));
    }

    private static string CreateSignedToken(string tokenType, string payloadJson)
    {
        var header = Base64Url.Encode(Encoding.UTF8.GetBytes($"{{\"alg\":\"HS256\",\"typ\":\"{tokenType}\"}}"));
        var payload = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));
        var signingInput = $"{header}.{payload}";
        var signature = Base64Url.Encode(new Symmetric256().Generate(signingInput, new TestConfiguration().Secret));

        return $"{signingInput}.{signature}";
    }

    private sealed class BrokenSignature : ISignature
    {
        public string Alg => Symmetric256.AlgName;
        public byte[] Generate(string input, string secret) => throw new InvalidOperationException("Signature implementation failed");
    }
}
