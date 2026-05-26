namespace KeyGenerator;

public abstract record Key<TKey, TPayload> where TKey : class
{
    public abstract Header Header { get; }

    public TPayload Payload { get; init; } = default!;

    public string Token { get; init; } = null!;

    protected abstract ISignature Signature { get; }

    public virtual Result Verify(TimeProvider timeProvider)
    {
        return Result.Success();
    }
}
