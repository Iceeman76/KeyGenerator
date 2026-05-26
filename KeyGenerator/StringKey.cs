namespace KeyGenerator;

public sealed record StringKey : Key<StringKey, string>
{
    public override Header Header { get; } = new()
    {
        Alg = Symmetric64.Alg,
        Typ = "STRING",
        Ver = 1
    };

    protected override ISignature Signature { get; } = Signatures.Symmetric64;
}
