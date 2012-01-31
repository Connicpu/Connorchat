using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Threading;

namespace ConnorcpuChatServer
{
    class Program
    {
        delegate void ClientHandleD(TcpClient client);

        static ClientHandleD HandleClient;

        static void Main(string[] args)
        {
            var port = 1526;

            if (args.Length > 0)
            {
                int _port;
                if (int.TryParse(args[0], out _port))
                {
                    port = _port;
                }
            }

            var listener = new TcpListener(IPAddress.Any, port);
            listener.Start();

            Console.WriteLine("Listening for clients.");

            HandleClient = client => new Thread(() => ClientHandler.HandleClient(client)).Start();

            while (true)
            {
                try
                {
                    var client = listener.AcceptTcpClient();
                    Console.WriteLine(client.Client.RemoteEndPoint + " connected.");
                    HandleClient(client);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }
    }
}
