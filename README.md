# KeyGenerator

A simple and extensible .NET library for generating and verifying signed tokens, inspired by the JWT (RFC 7519) structure.

## Features

- **JWT-inspired structure**: Tokens consist of three Base64Url-encoded parts: Header, Payload, and Signature.
- **Strongly typed payloads**: Use C# records to define structured data for your tokens.
- **Multiple Algorithms**:
  - `HS256`: HMAC-SHA256 (256-bit signature).
  - `HS512`: HMAC-SHA512 (512-bit signature).
  - `HS64`: HMAC-SHA256 truncated to 64 bits (useful for shorter tokens where full security isn't required).
- **CamelCase JSON support**: Automatically handles naming policies for JSON serialization/deserialization.
- **Extensible Architecture**: Easily implement new signature algorithms by implementing the `ISignature` interface.

## Getting Started

### 1. Implement IKeyConfiguration

You need to provide a secret key for the HMAC algorithms.

```csharp
public class MyKeyConfig : IKeyConfiguration
{
    public string Secret => "your-256-bit-secret-key-goes-here";
}
```

### 2. Define a Custom Key and Payload

Inherit from `Key<TKey, TPayload>` to create your own token types.

```csharp
public record UserPayload
{
    public required string UserId { get; init; }
    public required string Role { get; init; }
}

public sealed record UserKey : Key<UserKey, UserPayload>
{
    public override Header Header { get; } = new() 
    { 
        Alg = Symmetric256.Alg, 
        Typ = "USER" 
    };

    protected override ISignature Signature { get; } = Signatures.Symmetric256;
}
```

### 3. Initialize KeyService

```csharp
var config = new MyKeyConfig();
var signatures = new ISignature[] 
{ 
    Signatures.Symmetric256,
    Signatures.Symmetric512,
    Signatures.Symmetric64
};

var keyService = new KeyService(config, signatures);
```

### 4. Create and Parse Tokens

```csharp
// Create a token
var key = new UserKey 
{ 
    Payload = new UserPayload { UserId = "123", Role = "Admin" } 
};
string token = keyService.CreateToken(key);

// Parse and verify a token
var result = keyService.ParseToken<UserKey, UserPayload>(token);

if (result.IsSuccess)
{
    UserKey parsedKey = result.Value;
    Console.WriteLine($"Validated User: {parsedKey.Payload.UserId}");
}
else
{
    Console.WriteLine($"Error: {result.Problem}");
}
```

## Built-in Key Types

### ApiKey
A pre-defined key type for API authentication following common JWT claims.
- **Payload**: `Sub`, `Iat`, `Exp`, `Scopes`.
- **Algorithm**: HS256.
- **Type**: API.

### StringKey
A simple key for wrapping a single string value.
- **Payload**: `Value`.
- **Algorithm**: HS64.
- **Type**: STRING.
