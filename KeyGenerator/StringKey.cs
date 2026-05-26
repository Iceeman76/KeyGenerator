namespace KeyGenerator;

public record StringKey : Key<StringKey, string>
{
    public override Header Header { get; } = new() { Alg = Symmetric64.Alg, Typ = "STRING", Ver = 1 };
    protected override ISignature Signature { get; } = Signatures.Symmetric64;

    private StringKey()
    {
    }

    private StringKey(string str)
    {
        Payload = str;
        Token = CreateToken();
    }

    public static StringKey Create(string str) => new(str);
    public static Result<StringKey> Parse(string token) => new StringKey().ParseToken(token);
}
