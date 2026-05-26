namespace KeyGenerator;

public sealed record Header
{
    public required string Alg { get; init; }
    public required string Typ { get; init; }
    public required uint Ver { get; init; }
}
