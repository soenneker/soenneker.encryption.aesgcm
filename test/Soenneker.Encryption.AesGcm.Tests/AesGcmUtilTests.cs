using System;
using System.Security.Cryptography;
using System.Text;
using AwesomeAssertions;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Encryption.AesGcm.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class AesGcmUtilTests : HostedUnitTest
{
    public AesGcmUtilTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {
        typeof(AesGcmUtil).Should().NotBeNull();
    }

    [Test]
    public void Encrypt_and_decrypt_roundtrip_string()
    {
        const string key = "leadping-development-test-key";
        const string secret = "super-secret-webhook-token";

        string encrypted = AesGcmUtil.Encrypt(secret, key);

        encrypted.Should().StartWith($"{AesGcmConstants.DefaultPrefix}:");
        encrypted.Should().NotContain(secret);
        AesGcmUtil.Decrypt(encrypted, key).Should().Be(secret);
    }

    [Test]
    public void Encrypt_uses_random_nonce_each_time()
    {
        const string key = "leadping-development-test-key";
        const string secret = "super-secret-webhook-token";

        string first = AesGcmUtil.Encrypt(secret, key);
        string second = AesGcmUtil.Encrypt(secret, key);

        first.Should().NotBe(second);
        AesGcmUtil.Decrypt(first, key).Should().Be(secret);
        AesGcmUtil.Decrypt(second, key).Should().Be(secret);
    }

    [Test]
    public void Decrypt_supports_base64_encoded_256_bit_key()
    {
        string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        const string secret = "super-secret-webhook-token";

        string encrypted = AesGcmUtil.Encrypt(secret, key);

        AesGcmUtil.Decrypt(encrypted, key).Should().Be(secret);
    }

    [Test]
    public void Decrypt_requires_same_associated_data()
    {
        const string key = "leadping-development-test-key";
        const string secret = "super-secret-webhook-token";
        const string associatedData = "business-1:generic-webhook";

        string encrypted = AesGcmUtil.Encrypt(secret, key, associatedData);

        AesGcmUtil.Decrypt(encrypted, key, associatedData).Should().Be(secret);
        AesGcmUtil.TryDecrypt(encrypted, key, out string? plaintext, "business-2:generic-webhook").Should().BeFalse();
        plaintext.Should().BeNull();
    }

    [Test]
    public void Byte_payload_roundtrip()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = Encoding.UTF8.GetBytes("payload bytes");
        byte[] associatedData = Encoding.UTF8.GetBytes("tenant-1");

        AesGcmEncryptedPayload payload = AesGcmUtil.Encrypt(plaintext, key, associatedData);
        byte[] decrypted = AesGcmUtil.Decrypt(payload, key, associatedData);

        decrypted.Should().Equal(plaintext);
    }

    [Test]
    public void BuildKey_hashes_non_aes_sized_key_material()
    {
        byte[] key = AesGcmUtil.BuildKey("leadping-development-test-key");

        key.Length.Should().Be(32);
    }

    [Test]
    public void TryDecrypt_returns_false_for_malformed_payload()
    {
        bool result = AesGcmUtil.TryDecrypt("not-encrypted", "leadping-development-test-key", out string? plaintext);

        result.Should().BeFalse();
        plaintext.Should().BeNull();
    }
}
