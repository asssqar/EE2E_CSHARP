using System.Security.Cryptography;
using System.Text;

namespace E2EE;

/// Общая крипто-утилита: AES-256-CBC + HMAC-SHA256.

public static class CryptoHelper
{
    // ─── AES-256-CBC ───────────────────────────────────────────────────────────
  
    /// Шифрует строку.
    /// Формат возвращаемого массива: 
 
    public static byte[] Encrypt(string plaintext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key     = key;           // 32 байта = AES-256
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var ms        = new MemoryStream();
        using var encryptor = aes.CreateEncryptor();
        using var cs        = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        byte[] src = Encoding.UTF8.GetBytes(plaintext);
        cs.Write(src);
        cs.FlushFinalBlock();

        byte[] cipher = ms.ToArray();
        byte[] result = new byte[16 + cipher.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, 16);
        Buffer.BlockCopy(cipher, 0, result, 16, cipher.Length);
        return result;
    }


    /// Дешифрует данные 

    public static string Decrypt(byte[] data, byte[] key)
    {
        if (data.Length < 17)
            throw new ArgumentException("Данные слишком короткие для расшифровки.");

        using var aes = Aes.Create();
        aes.Key     = key;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.IV      = data[..16];

        using var ms        = new MemoryStream(data[16..]);
        using var decryptor = aes.CreateDecryptor();
        using var cs        = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr        = new StreamReader(cs, Encoding.UTF8);
        return sr.ReadToEnd();
    }

    // ─── HMAC-SHA256 ───────────────────────────────────────────────────────────

    public static byte[] ComputeHmac(byte[] data, byte[] key)
        => HMACSHA256.HashData(key, data);

    /// Проверяет HMAC в постоянное время (защита от timing-атак)
    public static bool VerifyHmac(byte[] data, byte[] key, byte[] expected)
        => CryptographicOperations.FixedTimeEquals(ComputeHmac(data, key), expected);

    // ─── Сетевые хелперы ───────────────────────────────────────────────────────

    /// Отправляет пакет

    public static void SendPacket(Stream stream, byte[] data)
    {
        byte[] lenBytes = BitConverter.GetBytes(data.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
        stream.Write(lenBytes);
        stream.Write(data);
        stream.Flush();
    }

    /// Читает пакет: [4 байта длина | данные].

    public static byte[] ReceivePacket(Stream stream)
    {
        byte[] lenBuf = ReadExact(stream, 4);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBuf);
        int length = BitConverter.ToInt32(lenBuf);
        return ReadExact(stream, length);
    }

    private static byte[] ReadExact(Stream stream, int count)
    {
        byte[] buf  = new byte[count];
        int    read = 0;
        while (read < count)
        {
            int n = stream.Read(buf, read, count - read);
            if (n == 0) throw new EndOfStreamException("Соединение закрыто.");
            read += n;
        }
        return buf;
    }
}
