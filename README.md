[![](https://img.shields.io/nuget/v/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.encryption.aesgcm/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.encryption.aesgcm/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.encryption.aesgcm/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.encryption.aesgcm/actions/workflows/codeql.yml)

# Soenneker.Encryption.AesGcm

Authenticated encryption for strings and byte payloads using AES-GCM, random nonces, optional associated data, and a versioned string envelope.

## Install

```bash
dotnet add package Soenneker.Encryption.AesGcm
```

## Encrypt and decrypt a string

```csharp
using System.Security.Cryptography;
using Soenneker.Encryption.AesGcm;

byte[] keyBytes = RandomNumberGenerator.GetBytes(32);
string keyMaterial = Convert.ToBase64String(keyBytes);
CryptographicOperations.ZeroMemory(keyBytes);

const string context = "tenant-42:api-token";

string encrypted = AesGcmUtil.Encrypt(
    "secret value",
    keyMaterial,
    associatedData: context);

string plaintext = AesGcmUtil.Decrypt(
    encrypted,
    keyMaterial,
    associatedData: context);
```

Each encryption generates a new 12-byte nonce, so encrypting the same value twice produces different output. The encoded format is:

```text
v1:<base64 nonce>:<base64 ciphertext>:<base64 authentication tag>
```

Associated data is authenticated but neither encrypted nor stored in the payload. Decryption must receive the exact same bytes or string; a mismatch fails authentication.

## Handle untrusted ciphertext

```csharp
if (!AesGcmUtil.TryDecrypt(encrypted, keyMaterial, out string? value, context))
{
    // Malformed envelope, wrong key/context, or failed authentication.
}
```

`Decrypt` throws for malformed envelopes, invalid key material, an unexpected prefix, or authentication failure. `TryDecrypt` converts those expected input failures into `false` and sets the output to null.

## Encrypt bytes

```csharp
byte[] key = RandomNumberGenerator.GetBytes(32);
byte[] data = "secret value"u8.ToArray();
byte[] contextBytes = "tenant-42:api-token"u8.ToArray();

AesGcmEncryptedPayload payload = AesGcmUtil.Encrypt(data, key, contextBytes);
byte[] decrypted = AesGcmUtil.Decrypt(payload, key, contextBytes);

CryptographicOperations.ZeroMemory(key);
CryptographicOperations.ZeroMemory(data);
CryptographicOperations.ZeroMemory(decrypted);
```

The raw payload exposes mutable nonce, ciphertext, and tag arrays. Store or transmit all three, and do not modify them before decryption.

## Key material

Use a cryptographically random 16-, 24-, or preferably 32-byte key stored in a secret manager. For the string API, Base64-encode those bytes as shown above. If a string is not Base64 that decodes to an AES key length, `BuildKey(string)` hashes its UTF-8 bytes once with SHA-256. That behavior is a deterministic compatibility conversion, not password hardening: do not pass a human password or other low-entropy secret. Derive password-based keys with an appropriate salted, work-factored KDF before calling this package.

For byte APIs, key material of an AES key length is copied directly; other non-empty input is SHA-256 hashed. `BuildKey` returns key bytes owned by the caller, who should clear them with `CryptographicOperations.ZeroMemory` when finished.

## Versioning and rotation

The prefix defaults to `v1` and is checked exactly during decryption. It is a format marker, not an authenticated key identifier. Keep the expected prefix and allowed keys under application policy; do not trust an incoming prefix to select arbitrary key material. For rotation, store a trusted key identifier alongside the encrypted value and retain old keys only for the required migration window.

Never reuse a nonce with the same AES key. The high-level encryption methods generate nonces with `RandomNumberGenerator`; if you construct raw payloads elsewhere, nonce uniqueness is your responsibility.
