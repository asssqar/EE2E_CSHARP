using System.Net;
using System.Net.Sockets;
using E2EE;

/// Ретрансляционный сервер: принимает подключения от Алисы и Боба,
/// пересылает зашифрованные пакеты между ними.

class RelayServer
{
    const int    PORT        = 65432;
    const string HOST        = "127.0.0.1";
    const int    MAX_CLIENTS = 2;   // Alice + Bob

    // Список подключённых клиентов и их потоки
    static readonly List<TcpClient>    clients = [];
    static readonly List<NetworkStream> streams = [];
    static readonly object             lockObj = new();

    static async Task Main()
    {
        Console.WriteLine($"[Server] Запуск ретрансляционного сервера на {HOST}:{PORT}");
        Console.WriteLine($"[Server] Ожидание {MAX_CLIENTS} клиентов...\n");

        var listener = new TcpListener(IPAddress.Parse(HOST), PORT);
        listener.Start();

        while (true)
        {
            TcpClient client = await listener.AcceptTcpClientAsync();
            lock (lockObj)
            {
                clients.Add(client);
                streams.Add(client.GetStream());
                Console.WriteLine($"[Server] Клиент #{clients.Count} подключился: " +
                                  $"{client.Client.RemoteEndPoint}");
            }

            // Начинаем обработку клиента в отдельном потоке
            _ = Task.Run(() => HandleClient(client));
        }
    }

    static async Task HandleClient(TcpClient client)
    {
        NetworkStream stream = client.GetStream();
        int myIndex;
        lock (lockObj) myIndex = clients.IndexOf(client);

        try
        {
            while (true)
            {
                // Читаем зашифрованный пакет от этого клиента
                byte[] packet = CryptoHelper.ReceivePacket(stream);
                Console.WriteLine($"[Server] Ретрансляция пакета {packet.Length} байт " +
                                  $"от клиента #{myIndex + 1}");

                // Пересылаем всем остальным клиентам
                lock (lockObj)
                {
                    for (int i = 0; i < streams.Count; i++)
                    {
                        if (i != myIndex && clients[i].Connected)
                        {
                            try { CryptoHelper.SendPacket(streams[i], packet); }
                            catch { /* клиент отключился */ }
                        }
                    }
                }
            }
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException)
        {
            Console.WriteLine($"[Server] Клиент #{myIndex + 1} отключился.");
            lock (lockObj)
            {
                streams.RemoveAt(myIndex);
                clients.RemoveAt(myIndex);
            }
        }
    }
}
