using System.Text;
using System.Text.Json;

namespace KeyGenerator;

public abstract record Key<TKey, TPayload> where TKey : class
{
    private const string Secret = "super-secret";

    public abstract Header Header { get; }
    public TPayload Payload { get; protected set; } = default!;
    public string Token { get; protected set; } = null!;

    protected abstract ISignature Signature { get; }

    public virtual Result Verify() => Result.Success();

    protected TKey Initialize()
    {
        Token = CreateToken();

        return (this as TKey)!;
    }

    protected string CreateToken()
    {
        var headerJson = JsonSerializer.Serialize(Header);
        var headerBytes = Encoding.UTF8.GetBytes(headerJson);
        var headerEncoded = KeyStatics.Base64UrlEncode(headerBytes);
        var headerLengthHex = headerEncoded.Length.ToString("X2");

        var payloadJson = JsonSerializer.Serialize(Payload);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var payloadEncoded = KeyStatics.Base64UrlEncode(payloadBytes);

        var dataToSign = $"{headerLengthHex}{headerEncoded}{payloadEncoded}";
        var signature = Signature.Generate(dataToSign, Secret);
        var unifiedKey = $"{dataToSign}{signature}";

        return unifiedKey;
    }

    protected Result<TKey> ParseToken(string token)
    {
        try
        {
            var headerLength = KeyStatics.GetHeaderLength(token);
            var headerResult = KeyStatics.ParseHeader(token, headerLength);
            if (headerResult.IsFailure) return headerResult.Problem;

            var header = headerResult.Value;
            if (header != Header) return $"Headers mismatch. Expected {Header} but was {header}";

            var payloadStart = KeyStatics.HeaderStart + headerLength;
            var payloadEnd = token.Length - Signature.Length;

            var payloadEncoded = token.Substring(payloadStart, payloadEnd - payloadStart);
            var signature = token.Substring(token.Length - Signature.Length, Signature.Length);

            var dataToVerify = token[..^Signature.Length];
            var expectedSignature = Signature.Generate(dataToVerify, Secret);
            if (string.Equals(signature, expectedSignature, StringComparison.OrdinalIgnoreCase) == false) return "Invalid signature";

            var payloadBytes = Convert.FromBase64String(KeyStatics.PadBase64(payloadEncoded));
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);

            Payload = JsonSerializer.Deserialize<TPayload>(payloadJson)!;

            return (this as TKey)!;
        }
        catch (JsonException)
        {
            return "Malformed json";
        }
        catch
        {
            return "Invalid format";
        }
    }
}
