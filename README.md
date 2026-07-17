[![](https://img.shields.io/nuget/v/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.encryption.aesgcm/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.encryption.aesgcm/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Encryption.AesGcm
### A .NET utility wrapping AES-GCM BCL for symmetric encryption.

## Installation

```
dotnet add package Soenneker.Encryption.AesGcm
```

## Usage

```csharp
using Soenneker.Encryption.AesGcm;

string encrypted = AesGcmUtil.Encrypt("super-secret-webhook-token", "configured-key-material");
string decrypted = AesGcmUtil.Decrypt(encrypted, "configured-key-material");
```

The default string payload format is:

```text
v1:<base64 nonce>:<base64 ciphertext>:<base64 tag>
```

For authenticated context binding, pass associated data during both encryption and decryption:

```csharp
string encrypted = AesGcmUtil.Encrypt(secret, key, associatedData: "business-1:generic-webhook");
string decrypted = AesGcmUtil.Decrypt(encrypted, key, associatedData: "business-1:generic-webhook");
```

Key material can be a base64 encoded 128-bit, 192-bit, or 256-bit AES key. Other key material is hashed with SHA-256 into a 256-bit AES key.
