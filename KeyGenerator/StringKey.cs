using KeyGenerator.Signatures;

namespace KeyGenerator;

public sealed record StringKey : Key<StringKey, StringKey.Definition>
{
    public override Header Header { get; } = new()
    {
        Alg = Symmetric64.AlgName,
        Typ = "STRING"
    };

    public sealed record Definition
    {
        public required string Value { get; init; }
    }

    public override Result Verify(TimeProvider timeProvider)
    {
        return Result.Success();
    }
}
