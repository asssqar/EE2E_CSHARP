using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

/// Генератор ключей: X25519 обмен + AES-256-CBC шифрование/дешифрование.

class KeyGen
{
    static void Main()
    {
        Console.WriteLine("=== E2EE Key Generator (X25519 + AES-256-CBC) ===\n");

        // Генерация пар ключей для Алисы и Боба
        var (alicePrivate, alicePublic) = GenerateX25519KeyPair();
        var (bobPrivate, bobPublic)     = GenerateX25519KeyPair();

        string alicePubHex = Convert.ToHexString(alicePublic);
        string bobPubHex   = Convert.ToHexString(bobPublic);

        Console.WriteLine($"[Alice] Публичный ключ : {alicePubHex}");
        Console.WriteLine($"[Bob]   Публичный ключ : {bobPubHex}\n");

        // X25519 ECDH — каждая сторона вычисляет общий секрет
        byte[] aliceShared = ComputeSharedSecret(alicePrivate, bobPublic);
        byte[] bobShared   = ComputeSharedSecret(bobPrivate, alicePublic);

        // Убеждаемся что оба пришли к одному секрету
        bool match = aliceShared.SequenceEqual(bobShared);
        Console.WriteLine($"Общий секрет совпадает: {match}");

        // Derive 32-byte AES key via SHA-256
        byte[] aesKey = SHA256.HashData(aliceShared);
        string sharedKeyHex = Convert.ToHexString(aesKey);
        Console.WriteLine($"\nСгенерированный общий ключ (hex):\n{sharedKeyHex}\n");

        // Демонстрация шифрования/дешифрования
        Console.Write("Введите тестовое сообщение для шифрования: ");
        string message = Console.ReadLine() ?? "Привет, мир!";

        byte[] encrypted = Encrypt(message, aesKey);
        string encryptedHex = Convert.ToHexString(encrypted);
        Console.WriteLine($"\nЗашифровано (hex): {encryptedHex}");

        string decrypted = Decrypt(encrypted, aesKey);
        Console.WriteLine($"Расшифровано    : {decrypted}");

        // HMAC проверка целостности
        byte[] hmac = ComputeHmac(encrypted, aesKey);
        Console.WriteLine($"\nHMAC-SHA256: {Convert.ToHexString(hmac)}");
        Console.WriteLine($"HMAC проверка пройдена: {VerifyHmac(encrypted, aesKey, hmac)}");

        Console.WriteLine("\nСкопируйте общий ключ и используйте его в Alice.cs и Bob.cs");
    }

    // ─── X25519 ────

    public static (byte[] privateKey, byte[] publicKey) GenerateX25519KeyPair()
    {
        var random = new SecureRandom();
        var gen    = new X25519KeyPairGenerator();
        gen.Init(new X25519KeyGenerationParameters(random));
        var kp = gen.GenerateKeyPair();

        var priv = new byte[32];
        var pub  = new byte[32];
        ((X25519PrivateKeyParameters)kp.Private).Encode(priv, 0);
        ((X25519PublicKeyParameters)kp.Public).Encode(pub, 0);
        return (priv, pub);
    }

    public static byte[] ComputeSharedSecret(byte[] privateKey, byte[] peerPublicKey)
    {
        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey));
        var shared = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublicKey), shared, 0);
        return shared;
    }

    // ─── AES-256-CBC ───

    ///Шифрует строку
    public static byte[] Encrypt(string plaintext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key     = key;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var ms        = new MemoryStream();
        using var encryptor = aes.CreateEncryptor();
        using var cs        = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

        byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
        cs.Write(plaintextBytes);
        cs.FlushFinalBlock();

        // Prepend IV
        byte[] ciphertext = ms.ToArray();
        byte[] result     = new byte[aes.IV.Length + ciphertext.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(ciphertext, 0, result, aes.IV.Length, ciphertext.Length);
        return result;
    }

    /// Дешифрует данные 
    public static string Decrypt(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key     = key;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        byte[] iv         = data[..16];
        byte[] ciphertext = data[16..];
        aes.IV = iv;

        using var ms        = new MemoryStream(ciphertext);
        using var decryptor = aes.CreateDecryptor();
        using var cs        = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader    = new StreamReader(cs, System.Text.Encoding.UTF8);
        return reader.ReadToEnd();
    }

    // ─── HMAC-SHA256 ────

    public static byte[] ComputeHmac(byte[] data, byte[] key)
        => HMACSHA256.HashData(key, data);

    public static bool VerifyHmac(byte[] data, byte[] key, byte[] expectedHmac)
        => CryptographicOperations.FixedTimeEquals(ComputeHmac(data, key), expectedHmac);
}
