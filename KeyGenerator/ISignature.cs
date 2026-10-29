namespace DotNetLab.KeyGenerator;

public interface ISignature
{
    string Alg { get; }
    public byte[] Generate(string input, string secret);
}
