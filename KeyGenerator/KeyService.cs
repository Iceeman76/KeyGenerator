using System.Text;
using System.Text.Json;

namespace KeyGenerator;

public sealed class KeyService : IKeyService
{
    private readonly IKeyConfiguration _configuration;
    private readonly IEnumerable<ISignature> _signatures;

    public KeyService(IKeyConfiguration configuration, IEnumerable<ISignature> signatures)
    {
        _configuration = configuration;
        _signatures = signatures;
    }

    public string CreateToken<TKey, TPayload>(Key<TKey, TPayload> key) where TKey : class
    {
        var headerJson = JsonSerializer.Serialize(key.Header);
        var headerBytes = Encoding.UTF8.GetBytes(headerJson);
        var headerEncoded = KeyStatics.Base64UrlEncode(headerBytes);
        var headerLengthHex = headerEncoded.Length.ToString("X4");

        var payloadJson = JsonSerializer.Serialize(key.Payload);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        var payloadEncoded = KeyStatics.Base64UrlEncode(payloadBytes);

        var dataToSign = $"{headerLengthHex}{headerEncoded}{payloadEncoded}";
        var signature = GetSignature(key.Header.Alg).Generate(dataToSign, _configuration.Secret);

        return $"{dataToSign}{signature}";
    }

    public Result<TKey> ParseToken<TKey, TPayload>(string token) where TKey : Key<TKey, TPayload>, new()
    {
        try
        {
            var headerLength = KeyStatics.GetHeaderLength(token);
            var headerResult = KeyStatics.ParseHeader(token, headerLength);

            if (headerResult.IsFailure)
            {
                return headerResult.Problem;
            }

            var header = headerResult.Value;
            var key = new TKey();

            if (header != key.Header)
            {
                return $"Headers mismatch. Expected {key.Header} but was {header}";
            }

            var signatureAlgorithm = GetSignature(header.Alg);
            var payloadStart = KeyStatics.HeaderStart + headerLength;
            var payloadEnd = token.Length - signatureAlgorithm.Length;

            if (payloadEnd < payloadStart)
            {
                return "Token is too short";
            }

            var payloadEncoded = token.Substring(payloadStart, payloadEnd - payloadStart);
            var signature = token.Substring(token.Length - signatureAlgorithm.Length, signatureAlgorithm.Length);

            var dataToVerify = token[..^signatureAlgorithm.Length];
            var expectedSignature = signatureAlgorithm.Generate(dataToVerify, _configuration.Secret);

            if (string.Equals(signature, expectedSignature, StringComparison.OrdinalIgnoreCase) == false)
            {
                return "Invalid signature";
            }

            var payloadBytes = Convert.FromBase64String(KeyStatics.PadBase64(payloadEncoded));
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            var payload = JsonSerializer.Deserialize<TPayload>(payloadJson);

            return key with { Payload = payload!, Token = token };
        }
        catch (JsonException)
        {
            return "Malformed json";
        }
        catch (Exception ex)
        {
            return $"Invalid format: {ex.Message}";
        }
    }

    private ISignature GetSignature(string alg)
    {
        var signature = _signatures.FirstOrDefault(s => GetAlgName(s) == alg);

        if (signature is null)
        {
            throw new NotSupportedException($"Algorithm {alg} is not supported");
        }

        return signature;
    }

    private static string GetAlgName(ISignature signature)
    {
        return signature switch
        {
            Symmetric64 => Symmetric64.Alg,
            Symmetric256 => Symmetric256.Alg,
            Symmetric512 => Symmetric512.Alg,
            _ => throw new NotSupportedException()
        };
    }
}
