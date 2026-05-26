namespace KeyGenerator;

internal static class Base64Url
{
    internal static string Encode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    internal static byte[] Decode(string input)
    {
        var output = input.Replace('-', '+').Replace('_', '/');

        switch (output.Length % 4)
        {
            case 2:
                output += "==";
                break;
            case 3:
                output += "=";
                break;
        }

        return Convert.FromBase64String(output);
    }
}
