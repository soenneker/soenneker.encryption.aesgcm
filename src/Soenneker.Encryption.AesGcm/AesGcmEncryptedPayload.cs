using System;

namespace Soenneker.Encryption.AesGcm;

/// <summary>
/// Represents the raw AES-GCM encryption output.
/// </summary>
public sealed record AesGcmEncryptedPayload(byte[] Nonce, byte[] Ciphertext, byte[] Tag)
{
    /// <summary>
    /// Validates the nonce, ciphertext, and tag lengths.
    /// </summary>
    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(Nonce);
        ArgumentNullException.ThrowIfNull(Ciphertext);
        ArgumentNullException.ThrowIfNull(Tag);

        if (Nonce.Length != AesGcmConstants.NonceSizeInBytes)
            throw new ArgumentException($"AES-GCM nonce must be {AesGcmConstants.NonceSizeInBytes} bytes.", nameof(Nonce));

        if (Tag.Length != AesGcmConstants.TagSizeInBytes)
            throw new ArgumentException($"AES-GCM tag must be {AesGcmConstants.TagSizeInBytes} bytes.", nameof(Tag));
    }
}
