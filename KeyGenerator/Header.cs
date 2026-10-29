namespace DotNetLab.KeyGenerator;

public sealed record Header
{
    public required string Alg { get; init; }
    public required string Typ { get; init; }
}
