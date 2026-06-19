namespace Soenneker.Encryption.AesGcm;

/// <summary>
/// Constants used by the AES-GCM utility.
/// </summary>
public static class AesGcmConstants
{
    /// <summary>
    /// The recommended AES-GCM nonce size in bytes.
    /// </summary>
    public const int NonceSizeInBytes = 12;

    /// <summary>
    /// The default AES-GCM authentication tag size in bytes.
    /// </summary>
    public const int TagSizeInBytes = 16;

    /// <summary>
    /// The default encoded payload version prefix.
    /// </summary>
    public const string DefaultPrefix = "v1";
}
