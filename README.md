# KeyGenerator

A small .NET 10 library for creating and parsing signed tokens with strongly typed payloads.

Tokens contain three Base64Url-encoded parts: `header.payload.signature`. HMAC protects their integrity. The payload is readable by anyone who has the token; it is **not encrypted**.

## Features

- Strongly typed payloads and camelCase JSON.
- HMAC-SHA256 (`HS256`) and HMAC-SHA512 (`HS512`).
- Built-in `ApiKey` and `StringKey`, both using HS256.
- Signature comparison with `CryptographicOperations.FixedTimeEquals`.
- Custom token types and signature implementations.
- Explicit validity checks with an injectable `TimeProvider`.
- No external dependencies in the library.

## Build and test

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0), then run:

```sh
dotnet restore KeyGenerator.slnx --locked-mode
dotnet build KeyGenerator.slnx --configuration Release --no-restore --warnaserror
dotnet test KeyGenerator.slnx --configuration Release --no-build
```

GitHub Actions runs these checks on pushes and pull requests to `main`. NuGet lock files are committed. To intentionally update dependencies, update the package references, run `dotnet restore KeyGenerator.slnx --force-evaluate`, and commit the resulting lock files.

## Use the library

Reference the library project from your application, adjusting the relative path:

```sh
dotnet add reference ../KeyGenerator/KeyGenerator/KeyGenerator.csproj
```

### Configure a secret

Generate a random secret once, and store it in your application's secret store. All instances creating or parsing the same tokens must use the same secret. Do not commit it to source control or generate a new one at every startup.

For a local PowerShell session:

```powershell
$env:KEYGENERATOR_SECRET = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
```

The library uses the UTF-8 bytes of the configured string directly; it does not Base64-decode the secret. Use at least 32 random bytes for HS256 or 64 for HS512 before encoding. Secret strength and storage are the caller's responsibility; the library does not enforce a minimum key length.

### Create, parse, and verify an API token

The following is a complete `Program.cs` example:

```csharp
using KeyGenerator;
using KeyGenerator.Signatures;

var secret = Environment.GetEnvironmentVariable("KEYGENERATOR_SECRET") ?? throw new InvalidOperationException("Set KEYGENERATOR_SECRET before running the application.");
var service = new KeyService(new KeyConfiguration(secret), [new Symmetric256()]);
var now = TimeProvider.System.GetUtcNow();
var key = new ApiKey
{
    Payload = new ApiKey.Definition
    {
        Sub = "user-123",
        Iat = now.ToUnixTimeSeconds(),
        Exp = now.AddHours(1).ToUnixTimeSeconds(),
        Scopes = ["read"]
    }
};

var token = service.CreateToken(key);
var parsed = service.ParseToken<ApiKey, ApiKey.Definition>(token);

if (parsed.IsSuccess is false)
{
    Console.WriteLine(parsed.Problem);

    return;
}

var validity = parsed.Value.Verify(TimeProvider.System);

if (validity.IsSuccess is false)
{
    Console.WriteLine(validity.Problem);

    return;
}

Console.WriteLine($"Valid token for {parsed.Value.Payload.Sub}");

public sealed class KeyConfiguration(string secret) : IKeyConfiguration
{
    public string Secret { get; } = secret;
}
```

`ParseToken` checks the expected header, signature, and payload deserialization. It rejects missing properties marked `required`, null payloads, and null values for non-nullable object properties. It **does not call `Verify`**. A correctly signed but expired token therefore parses successfully.

`ApiKey.Verify` rejects `exp` values at or before the current Unix timestamp. It does not validate `iat`, subject contents, or scope permissions. Your application must enforce its own authorization rules after parsing and verification.

Malformed Base64 or JSON and mismatched signatures return a failed `Result`. Unsupported algorithms and configuration or implementation errors can throw; configure the service with every algorithm its token types require. Read `Value` only on success and `Problem` only on failure.

### Wrap a string

Using the service above:

```csharp
var key = new StringKey { Payload = new StringKey.Definition { Value = "Hello world" } };
var token = service.CreateToken(key);
var parsed = service.ParseToken<StringKey, StringKey.Definition>(token);

if (parsed.IsSuccess)
{
    Console.WriteLine(parsed.Value.Payload.Value);
}
```

`StringKey` uses HS256 and has no expiry policy. Its `Verify` method always succeeds.

### Define a custom token

```csharp
using KeyGenerator;
using KeyGenerator.Signatures;

public sealed record UserPayload
{
    public required string UserId { get; init; }
    public required string Role { get; init; }
}

public sealed record UserKey : Key<UserKey, UserPayload>
{
    public override Header Header { get; } = new() { Alg = Symmetric512.AlgName, Typ = "USER" };
    public override Result Verify(TimeProvider timeProvider) => Result.Success();
}
```

Register `new Symmetric512()` with `KeyService` to use this type. Implement domain validity rules in `Verify`; the implementation above adds no validity checks.

## Format and security boundaries

This is a JWT-inspired signed-token library, not a complete JWT authentication or authorization implementation. It does not provide issuer or audience validation, `nbf`, clock skew, revocation, key rotation, or middleware integration. Use an established JWT authentication stack when those features are required.

`ApiKey` uses `typ: API`; `StringKey` uses `typ: STRING`. Parsing requires both the algorithm and token type to match the expected key type. HS256 and HS512 are standard HMAC algorithms, but the test suite does not establish full JWT interoperability.

`Symmetric64` is available for custom types. It truncates HMAC-SHA256 to eight bytes and uses the custom algorithm name `HS64`. It provides a much smaller forgery margin than HS256, is not a standard JWT algorithm, and should not be used for authentication or valuable authorization decisions. It is intended only for low-risk integrity checks where the shorter signature is a deliberate tradeoff.

Treat tokens as bearer credentials when they grant access. Use HTTPS, avoid logging tokens, and enforce request-size limits at the application boundary. Only issue tokens from trusted payloads. Nullability enforcement during JSON deserialization does not replace domain validation or validation of collection elements.

## Contributing

Keep changes focused, add NUnit tests for behavior changes, and run the build and test commands above before opening a pull request. Include a description of the problem, resulting behavior, and any compatibility changes.

## License

[MIT](LICENSE). Free to use, modify, distribute, sublicense, and sell, including in commercial projects. Keep the copyright and license notice with copies or substantial portions of the code. The software is provided without warranty.
