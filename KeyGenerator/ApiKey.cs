namespace KeyGenerator;

public record ApiKey : Key<ApiKey, ApiKey.Definition>
{
    public override Header Header { get; } = new() { Alg = Symmetric256.Alg, Typ = "API", Ver = 1 };
    protected override ISignature Signature { get; } = Signatures.Symmetric256;

    private ApiKey()
    {
    }

    public record Definition
    {
        public required string Uid { get; init; }
        public required long Iat { get; init; }
        public required long Exp { get; init; }
        public required string[] Scopes { get; init; }
    }

    public static ApiKey Create(string userId, string[] scopes)
    {
        return new ApiKey
        {
            Payload = new Definition
            {
                Uid = userId,
                Scopes = scopes,
                Iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
            }
        }.Initialize();
    }

    public static Result<ApiKey> Parse(string token) => new ApiKey().ParseToken(token);
    public override Result Verify() => Payload.Exp > DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? Result.Success() : Result.Failure("Expired");
}