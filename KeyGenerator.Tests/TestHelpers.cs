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
    public override Header Header { get; } = new() { Alg = Symmetric512.Alg, Typ = "CUSTOM" };
    protected override ISignature Signature { get; } = Signatures.Symmetric512;
}
