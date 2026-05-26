using System.Globalization;
using System.Text;
using System.Text.Json;

namespace KeyGenerator;

internal static class KeyStatics
{
    public const int HeaderStart = 2;

    public static int GetHeaderLength(string token)
    {
        var headerLengthHex = token[..HeaderStart];
        var parsedSuccessfully = int.TryParse(headerLengthHex, NumberStyles.HexNumber, null, out var headerLength);

        return parsedSuccessfully ? headerLength : 0;
    }

    public static Result<Header> ParseHeader(string token, int headerLength)
    {
        try
        {
            var headerEncoded = token.Substring(HeaderStart, headerLength);
            var headerBytes = Convert.FromBase64String(PadBase64(headerEncoded));
            var headerJson = Encoding.UTF8.GetString(headerBytes);
            var header = JsonSerializer.Deserialize<Header>(headerJson)!;

            return header;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    public static string PadBase64(string input)
    {
        var padding = (4 - input.Length % 4) % 4;
        return input + new string('=', padding);
    }

    public static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    // public static string GenerateSignature(string input, string secret)
    // {
    //     var bytes = Encoding.UTF8.GetBytes(secret);
    //     using var hmac = new HMACSHA256(bytes);
    //
    //     var buffer = Encoding.UTF8.GetBytes(input);
    //     var hash = hmac.ComputeHash(buffer);
    //     var signature = Convert.ToHexStringLower(hash);
    //
    //     return signature;
    // }
}
