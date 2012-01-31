using System.Collections.Generic;

namespace ConnorcpuChatServer {
    internal static class UserManager {
        private static readonly Dictionary<string, Client> Clients =
            new Dictionary<string, Client>();
        internal static void RegisterClient(Client c) {
            Clients[c.u] = c;
        }

        internal static bool Connected(string user) {
            return Clients.ContainsKey(user) && Clients[user].Connected;
        }

        internal static void UnRegisterClient(Client user) {
            if (!Clients.ContainsKey(user.u)) return;
            Clients.Remove(user.u);
        }

        internal static int Message(this Client c, string target, string message) {
            if (!Connected(target)) {
                return 0xDCED;
            }

            Clients[target].Send("$" + c.u + ":" + message);

            return 0x0;
        }
    }
}