using System.Net.Sockets;
using System.Text;
using E2EE;


/// Клиент Алисы: шифрует сообщения AES-256-CBC + HMAC-SHA256
/// и отправляет через сервер-ретранслятор Бобу.
class Alice
{
    const string SERVER_HOST = "127.0.0.1";
    const int    SERVER_PORT = 65432;

    static async Task Main()
    {
        Console.WriteLine("=== Alice (отправитель) ===\n");

        // Получаем общий ключ (hex), заранее сгенерированный key_gen
        Console.Write("Введите общий ключ (hex, 64 символа): ");
        string? keyHex = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(keyHex) || keyHex.Length != 64)
        {
            Console.Error.WriteLine("[Alice] Неверный ключ. Запустите KeyGen и скопируйте ключ.");
            return;
        }

        byte[] sharedKey;
        try   { sharedKey = Convert.FromHexString(keyHex); }
        catch { Console.Error.WriteLine("[Alice] Ошибка разбора hex-ключа."); return; }

        // Подключение к серверу-ретранслятору
        using var tcp    = new TcpClient();
        await tcp.ConnectAsync(SERVER_HOST, SERVER_PORT);
        using NetworkStream stream = tcp.GetStream();
        Console.WriteLine($"[Alice] Подключена к серверу {SERVER_HOST}:{SERVER_PORT}\n");
        Console.WriteLine("[Alice] Введите сообщение (или 'exit' для выхода):\n");

        // Запускаем фоновую задачу для приёма ответов от Боба
        var receiveTask = Task.Run(() => ReceiveLoop(stream, sharedKey));

        // Основной цикл отправки
        while (true)
        {
            Console.Write("Alice > ");
            string? input = Console.ReadLine();
            if (input == null || input.Equals("exit", StringComparison.OrdinalIgnoreCase))
                break;
            if (string.IsNullOrWhiteSpace(input)) continue;

            try
            {
                // Шифруем сообщение
                byte[] encrypted = CryptoHelper.Encrypt(input, sharedKey);

                // Считаем HMAC от зашифрованных данных
                byte[] hmac = CryptoHelper.ComputeHmac(encrypted, sharedKey);

                // Пакет = [4 байта длина HMAC(32) | HMAC | зашифрованные данные]
                byte[] packet = BuildPacket(hmac, encrypted);

                CryptoHelper.SendPacket(stream, packet);
                Console.WriteLine($"[Alice] ✓ Отправлено (зашифровано, {encrypted.Length} байт)");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Alice] Ошибка отправки: {ex.Message}");
                break;
            }
        }

        Console.WriteLine("[Alice] Завершение работы.");
    }

    static void ReceiveLoop(NetworkStream stream, byte[] key)
    {
        try
        {
            while (true)
            {
                byte[] packet = CryptoHelper.ReceivePacket(stream);
                (byte[] hmac, byte[] encrypted) = SplitPacket(packet);

                if (!CryptoHelper.VerifyHmac(encrypted, key, hmac))
                {
                    Console.WriteLine("\n[Alice] ⚠️  HMAC не совпадает — сообщение может быть повреждено!");
                    continue;
                }

                string plaintext = CryptoHelper.Decrypt(encrypted, key);
                Console.WriteLine($"\n[Bob] → {plaintext}");
                Console.Write("Alice > ");
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException)
        {
            Console.WriteLine("\n[Alice] Соединение закрыто сервером.");
        }
    }

    /// Пакет = [4 байта длина HMAC | HMAC | encrypted]
    static byte[] BuildPacket(byte[] hmac, byte[] encrypted)
    {
        byte[] lenBytes = BitConverter.GetBytes(hmac.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);

        byte[] result = new byte[4 + hmac.Length + encrypted.Length];
        Buffer.BlockCopy(lenBytes,  0, result, 0,                  4);
        Buffer.BlockCopy(hmac,      0, result, 4,                  hmac.Length);
        Buffer.BlockCopy(encrypted, 0, result, 4 + hmac.Length,    encrypted.Length);
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
