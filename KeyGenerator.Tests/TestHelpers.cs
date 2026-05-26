using KeyGenerator.Signatures;

namespace KeyGenerator.Tests;

public sealed class TestConfiguration : IKeyConfiguration
{
    public string Secret => "test-secret-that-is-long-enough-for-security";
}

public static class TestServiceProvider
{
    public static IKeyService CreateKeyService()
    {
        var config = new TestConfiguration();
        var signatures = new ISignature[]
        {
            new Symmetric64(),
            new Symmetric256(),
            new Symmetric512()
        };
        
        return new KeyService(config, signatures);
    }
}

public sealed record CustomKey : Key<CustomKey, string>
{
    public override Header Header { get; } = new() { Alg = Symmetric512.AlgName, Typ = "CUSTOM" };

    public override Result Verify(TimeProvider timeProvider)
    {
        return Result.Success();
    }
}
