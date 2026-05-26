using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KeyGenerator;

public sealed class KeyService(IKeyConfiguration configuration, IEnumerable<ISignature> signatures) : IKeyService
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public string CreateToken<TKey, TPayload>(Key<TKey, TPayload> key) where TKey : class
    {
        var headerJson = JsonSerializer.Serialize(key.Header, Options);
        var headerEncoded = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson));

        var payloadJson = JsonSerializer.Serialize(key.Payload, Options);
        var payloadEncoded = Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson));

        var dataToSign = $"{headerEncoded}.{payloadEncoded}";
        var signatureBytes = GetSignature(key.Header.Alg).Generate(dataToSign, configuration.Secret);
        var signatureEncoded = Base64Url.Encode(signatureBytes);

        return $"{dataToSign}.{signatureEncoded}";
    }

    public Result<TKey> ParseToken<TKey, TPayload>(string token) where TKey : Key<TKey, TPayload>, new()
    {
        try
        {
            if (string.IsNullOrEmpty(token))
            {
                return "Invalid format";
            }

            var parts = token.Split('.');

            if (parts.Length != 3)
            {
                return "Invalid token format. Expected 3 parts.";
            }

            var headerEncoded = parts[0];
            var payloadEncoded = parts[1];
            var signatureEncoded = parts[2];

            var headerBytes = Base64Url.Decode(headerEncoded);
            var headerJson = Encoding.UTF8.GetString(headerBytes);
            var header = JsonSerializer.Deserialize<Header>(headerJson, Options)!;

            var key = new TKey();

            if (header != key.Header)
            {
                return $"Headers mismatch. Expected {key.Header} but was {header}";
            }

            var signatureAlgorithm = GetSignature(header.Alg);
            var dataToVerify = $"{headerEncoded}.{payloadEncoded}";
            var expectedSignatureBytes = signatureAlgorithm.Generate(dataToVerify, configuration.Secret);
            var signatureBytes = Base64Url.Decode(signatureEncoded);

            if (CryptographicOperations.FixedTimeEquals(signatureBytes, expectedSignatureBytes) == false)
            {
                return "Invalid signature";
            }

            var payloadBytes = Base64Url.Decode(payloadEncoded);
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            var payload = JsonSerializer.Deserialize<TPayload>(payloadJson, Options);

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
        var signature = signatures.FirstOrDefault(s => s.Alg == alg);

        return signature ?? throw new NotSupportedException($"Algorithm {alg} is not supported");
    }
}
