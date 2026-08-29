[![](https://img.shields.io/nuget/v/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.encryption.aesgcm/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.encryption.aesgcm/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.encryption.aesgcm.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.encryption.aesgcm/)

# Soenneker.Encryption.AesGcm

Constants used by the AES-GCM utility.

## Install

```bash
dotnet add package Soenneker.Encryption.AesGcm
```

## Quick start

```csharp
using Soenneker.Encryption.AesGcm;

var result = AesGcmUtil.Encrypt("value", "value");
```

Encrypts a UTF-8 string and returns an encoded payload in the format prefix:nonce:ciphertext:tag.

## What you get

- `AesGcmConstants` — Constants used by the AES-GCM utility.
- `AesGcmUtil` — A .NET utility wrapping AES-GCM BCL for symmetric encryption.
- `AesGcmEncryptedPayload` — Represents the raw AES-GCM encryption output.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `AesGcmConstants.NonceSizeInBytes` | The recommended AES-GCM nonce size in bytes. | The recommended AES-GCM nonce size in bytes. |
| `AesGcmConstants.TagSizeInBytes` | The default AES-GCM authentication tag size in bytes. | The default AES-GCM authentication tag size in bytes. |
| `AesGcmConstants.DefaultPrefix` | The default encoded payload version prefix. | The default encoded payload version prefix. |
| `AesGcmUtil.Encrypt(plaintext, keyMaterial, associatedData, prefix)` | Encrypts a UTF-8 string and returns an encoded payload in the format prefix:nonce:ciphertext:tag. | Returns `string`. |
| `AesGcmUtil.Decrypt(encryptedValue, keyMaterial, associatedData, expectedPrefix)` | Decrypts an encoded AES-GCM payload produced by `Encrypt(string,string,string?,string)`. | Returns `string`. |
| `AesGcmUtil.TryDecrypt(encryptedValue, keyMaterial, plaintext, associatedData, expectedPrefix)` | Attempts to decrypt an encoded AES-GCM payload without throwing for malformed payloads or authentication failures. | true if the requested update was applied; otherwise, false. |
| `AesGcmUtil.Encrypt(plaintext, keyMaterial)` | Encrypts bytes and returns the raw nonce, ciphertext, and authentication tag. | The resulting aes Gcm Encrypted Payload. |
| `AesGcmUtil.Encrypt(plaintext, keyMaterial, associatedData)` | Encrypts bytes with associated authenticated data and returns the raw nonce, ciphertext, and authentication tag. | The resulting aes Gcm Encrypted Payload. |
| `AesGcmUtil.Decrypt(payload, keyMaterial)` | Decrypts a raw AES-GCM payload. | The resulting byte[]. |
| `AesGcmUtil.Decrypt(payload, keyMaterial, associatedData)` | Decrypts a raw AES-GCM payload with associated authenticated data. | The resulting byte[]. |
| `AesGcmUtil.BuildKey(keyMaterial)` | Builds a usable AES key from configured key material. | The resulting byte[]. |
| `AesGcmEncryptedPayload.Validate()` | Validates the nonce, ciphertext, and tag lengths. | Returns no value; the requested change is complete when the method returns. |
