namespace KeyGenerator;

public sealed record StringKey : Key<StringKey, StringKey.Definition>
{
    public override Header Header { get; } = new()
    {
        Alg = Symmetric64.Alg,
        Typ = "STRING"
    };

    protected override ISignature Signature { get; } = Signatures.Symmetric64;

    public sealed record Definition
    {
        public required string Value { get; init; }
    }
}
