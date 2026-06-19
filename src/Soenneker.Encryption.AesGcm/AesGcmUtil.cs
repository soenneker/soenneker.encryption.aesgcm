using System;
using System.Security.Cryptography;
using System.Text;
using Soenneker.Extensions.String;

namespace Soenneker.Encryption.AesGcm;

/// <summary>
/// A .NET utility wrapping AES-GCM BCL for symmetric encryption.
/// </summary>
public static class AesGcmUtil
{
    /// <summary>
    /// Encrypts a UTF-8 string and returns an encoded payload in the format prefix:nonce:ciphertext:tag.
    /// </summary>
    public static string Encrypt(string plaintext, string keyMaterial, string? associatedData = null,
        string prefix = AesGcmConstants.DefaultPrefix)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ValidatePrefix(prefix);

        byte[] plaintextBytes = plaintext.ToBytes();
        byte[]? associatedDataBytes = associatedData is null ? null : associatedData.ToBytes();
        byte[]? key = null;

        try
        {
            key = BuildKey(keyMaterial);

            AesGcmEncryptedPayload payload = associatedDataBytes is null
                ? EncryptWithKey(plaintextBytes, key, ReadOnlySpan<byte>.Empty)
                : EncryptWithKey(plaintextBytes, key, associatedDataBytes);

            return Encode(payload, prefix);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);

            if (associatedDataBytes is not null)
                CryptographicOperations.ZeroMemory(associatedDataBytes);

            if (key is not null)
                CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Decrypts an encoded AES-GCM payload produced by <see cref="Encrypt(string,string,string?,string)"/>.
    /// </summary>
    public static string Decrypt(string encryptedValue, string keyMaterial, string? associatedData = null,
        string expectedPrefix = AesGcmConstants.DefaultPrefix)
    {
        ValidateKeyMaterial(keyMaterial);

        AesGcmEncryptedPayload payload = Decode(encryptedValue, expectedPrefix);
        byte[]? associatedDataBytes = associatedData is null ? null : associatedData.ToBytes();
        byte[]? key = null;
        byte[]? plaintextBytes = null;

        try
        {
            key = BuildKey(keyMaterial);
            plaintextBytes = associatedDataBytes is null
                ? DecryptWithKey(payload, key, ReadOnlySpan<byte>.Empty)
                : DecryptWithKey(payload, key, associatedDataBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            if (plaintextBytes is not null)
                CryptographicOperations.ZeroMemory(plaintextBytes);

            if (associatedDataBytes is not null)
                CryptographicOperations.ZeroMemory(associatedDataBytes);

            if (key is not null)
                CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Attempts to decrypt an encoded AES-GCM payload without throwing for malformed payloads or authentication failures.
    /// </summary>
    public static bool TryDecrypt(string encryptedValue, string keyMaterial, out string? plaintext,
        string? associatedData = null, string expectedPrefix = AesGcmConstants.DefaultPrefix)
    {
        try
        {
            plaintext = Decrypt(encryptedValue, keyMaterial, associatedData, expectedPrefix);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or FormatException
                                       or InvalidOperationException)
        {
            plaintext = null;
            return false;
        }
    }

    /// <summary>
    /// Encrypts bytes and returns the raw nonce, ciphertext, and authentication tag.
    /// </summary>
    public static AesGcmEncryptedPayload Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> keyMaterial)
    {
        return Encrypt(plaintext, keyMaterial, ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Encrypts bytes with associated authenticated data and returns the raw nonce, ciphertext, and authentication tag.
    /// </summary>
    public static AesGcmEncryptedPayload Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> keyMaterial,
        ReadOnlySpan<byte> associatedData)
    {
        byte[] key = BuildKey(keyMaterial);

        try
        {
            return EncryptWithKey(plaintext, key, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Decrypts a raw AES-GCM payload.
    /// </summary>
    public static byte[] Decrypt(AesGcmEncryptedPayload payload, ReadOnlySpan<byte> keyMaterial)
    {
        return Decrypt(payload, keyMaterial, ReadOnlySpan<byte>.Empty);
    }

    /// <summary>
    /// Decrypts a raw AES-GCM payload with associated authenticated data.
    /// </summary>
    public static byte[] Decrypt(AesGcmEncryptedPayload payload, ReadOnlySpan<byte> keyMaterial,
        ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(payload);
        payload.Validate();

        byte[] key = BuildKey(keyMaterial);

        try
        {
            return DecryptWithKey(payload, key, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Builds a usable AES key from configured key material.
    /// </summary>
    public static byte[] BuildKey(string keyMaterial)
    {
        ValidateKeyMaterial(keyMaterial);

        try
        {
            byte[] decoded = keyMaterial.ToBytesFromBase64();

            if (IsValidAesKeyLength(decoded.Length))
                return decoded;

            CryptographicOperations.ZeroMemory(decoded);
        }
        catch (FormatException)
        {
        }

        byte[] keyMaterialBytes = keyMaterial.ToBytes();

        try
        {
            return SHA256.HashData(keyMaterialBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterialBytes);
        }
    }

    /// <summary>
    /// Builds a usable AES key from configured key material bytes.
    /// </summary>
    public static byte[] BuildKey(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.IsEmpty)
            throw new ArgumentException("AES key material is required.", nameof(keyMaterial));

        if (IsValidAesKeyLength(keyMaterial.Length))
            return keyMaterial.ToArray();

        return SHA256.HashData(keyMaterial);
    }

    private static AesGcmEncryptedPayload EncryptWithKey(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcmConstants.NonceSizeInBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AesGcmConstants.TagSizeInBytes];

        using var aes = new System.Security.Cryptography.AesGcm(key, AesGcmConstants.TagSizeInBytes);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new AesGcmEncryptedPayload(nonce, ciphertext, tag);
    }

    private static byte[] DecryptWithKey(AesGcmEncryptedPayload payload, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData)
    {
        byte[] plaintext = new byte[payload.Ciphertext.Length];

        try
        {
            using var aes = new System.Security.Cryptography.AesGcm(key, AesGcmConstants.TagSizeInBytes);
            aes.Decrypt(payload.Nonce, payload.Ciphertext, payload.Tag, plaintext, associatedData);

            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    private static string Encode(AesGcmEncryptedPayload payload, string prefix)
    {
        payload.Validate();

        return
            $"{prefix}:{Convert.ToBase64String(payload.Nonce)}:{Convert.ToBase64String(payload.Ciphertext)}:{Convert.ToBase64String(payload.Tag)}";
    }

    private static AesGcmEncryptedPayload Decode(string encryptedValue, string expectedPrefix)
    {
        if (encryptedValue.IsNullOrWhiteSpace())
            throw new ArgumentException("AES-GCM encrypted value is required.", nameof(encryptedValue));

        ValidatePrefix(expectedPrefix);

        string[] parts = encryptedValue.Split(':');

        if (parts.Length != 4 || !string.Equals(parts[0], expectedPrefix, StringComparison.Ordinal))
            throw new FormatException("AES-GCM payload is not in a supported encrypted format.");

        byte[] nonce = parts[1].ToBytesFromBase64();
        byte[] ciphertext = parts[2].ToBytesFromBase64();
        byte[] tag = parts[3].ToBytesFromBase64();

        var payload = new AesGcmEncryptedPayload(nonce, ciphertext, tag);
        payload.Validate();

        return payload;
    }

    private static void ValidateKeyMaterial(string keyMaterial)
    {
        if (keyMaterial.IsNullOrWhiteSpace())
            throw new ArgumentException("AES key material is required.", nameof(keyMaterial));
    }

    private static void ValidatePrefix(string prefix)
    {
        if (prefix.IsNullOrWhiteSpace() || prefix.ContainsAny(':'))
            throw new ArgumentException("AES-GCM payload prefix is required and cannot contain ':'.", nameof(prefix));
    }

    private static bool IsValidAesKeyLength(int length)
    {
        return length is 16 or 24 or 32;
    }
}