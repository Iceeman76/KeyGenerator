namespace KeyGenerator;

public sealed record ApiKey : Key<ApiKey, ApiKey.Definition>
{
    public override Header Header { get; } = new() { Alg = Symmetric256.Alg, Typ = "API" };

    protected override ISignature Signature { get; } = Signatures.Symmetric256;

    public sealed record Definition
    {
        public required string Sub { get; init; }

        public required long Iat { get; init; }

        public required long Exp { get; init; }

        public required string[] Scopes { get; init; }
    }

    public override Result Verify(TimeProvider timeProvider)
    {
        var expired = Payload.Exp <= timeProvider.GetUtcNow().ToUnixTimeSeconds();

        return expired
            ? Result.Failure("Expired")
            : Result.Success();
    }
}
