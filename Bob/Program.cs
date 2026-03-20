using System.Net.Sockets;
using E2EE;


class Bob
{
    const string SERVER_HOST = "127.0.0.1";
    const int    SERVER_PORT = 65432;

    static async Task Main()
    {
        Console.WriteLine("=== Bob (получатель) ===\n");

        // Общий ключ, полученный от KeyGen
        Console.Write("Введите общий ключ (hex, 64 символа): ");
        string? keyHex = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
        {
            Console.Error.WriteLine("[Bob] Неверный ключ. Запустите KeyGen и скопируйте ключ.");
            return;
        }

        byte[] sharedKey;
        try   { sharedKey = Convert.FromHexString(keyHex); }
        catch { Console.Error.WriteLine("[Bob] Ошибка разбора hex-ключа."); return; }

        // Подключение к серверу-ретранслятору
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(SERVER_HOST, SERVER_PORT);
        using NetworkStream stream = tcp.GetStream();
        Console.WriteLine($"[Bob] Подключён к серверу {SERVER_HOST}:{SERVER_PORT}\n");
        Console.WriteLine("[Bob] Ожидание сообщений от Алисы...\n");

        // Фоновая задача приёма
        var receiveTask = Task.Run(() => ReceiveLoop(stream, sharedKey));

        // Основной цикл — Боб тоже может отправлять
        while (true)
        {
            Console.Write("Bob > ");
            string? input = Console.ReadLine();
            if (input == null || input.Equals("exit", StringComparison.OrdinalIgnoreCase))
                break;
            if (string.IsNullOrWhiteSpace(input)) continue;

            try
            {
                byte[] encrypted = CryptoHelper.Encrypt(input, sharedKey);
                byte[] hmac      = CryptoHelper.ComputeHmac(encrypted, sharedKey);
                byte[] packet    = BuildPacket(hmac, encrypted);
                CryptoHelper.SendPacket(stream, packet);
                Console.WriteLine($"[Bob] ✓ Отправлено ({encrypted.Length} байт)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Bob] Ошибка отправки: {ex.Message}");
                break;
            }
        }

        Console.WriteLine("[Bob] Завершение работы.");
    }

    static void ReceiveLoop(NetworkStream stream, byte[] key)
    {
        try
        {
            while (true)
            {
                byte[] packet = CryptoHelper.ReceivePacket(stream);
                (byte[] hmac, byte[] encrypted) = SplitPacket(packet);

                // Проверка целостности
                if (!CryptoHelper.VerifyHmac(encrypted, key, hmac))
                {
                    Console.WriteLine("\n[Bob] ⚠️  HMAC не совпадает — сообщение возможно подделано!");
                    continue;
                }

                string plaintext = CryptoHelper.Decrypt(encrypted, key);
                Console.WriteLine($"\n[Alice] → {plaintext}");
                Console.Write("Bob > ");
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException)
        {
            Console.WriteLine("\n[Bob] Соединение закрыто сервером.");
        }
    }

    static byte[] BuildPacket(byte[] hmac, byte[] encrypted)
    {
        byte[] lenBytes = BitConverter.GetBytes(hmac.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);

        byte[] result = new byte[4 + hmac.Length + encrypted.Length];
        Buffer.BlockCopy(lenBytes,  0, result, 0,               4);
        Buffer.BlockCopy(hmac,      0, result, 4,               hmac.Length);
        Buffer.BlockCopy(encrypted, 0, result, 4 + hmac.Length, encrypted.Length);
        return result;
    }

    static (byte[] hmac, byte[] encrypted) SplitPacket(byte[] packet)
    {
        byte[] lenBuf = packet[..4];
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBuf);
        int hmacLen = BitConverter.ToInt32(lenBuf);

        byte[] hmac      = packet[4..(4 + hmacLen)];
        byte[] encrypted = packet[(4 + hmacLen)..];
        return (hmac, encrypted);
    }
}
