using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using ConnorcpuChatCommon;

namespace ConnorcpuChatServer {
    internal class Client : IDisposable {
        private readonly TcpClient c;
        private readonly NetworkStream s;
        internal readonly string u;
        private readonly Aes a;
        private readonly Encoding e = Encoding.UTF8;
        
        internal Client(TcpClient c, string u, Aes a) {
            this.c = c;
            this.u = u;
            this.a = a;
            s = c.GetStream();
        }

        internal void Start() {
            new Thread(Loop).Start();
        }

        private void Loop() {
            UserManager.RegisterClient(this);
        }

        internal bool Connected {
            get { return c.Connected; }
        }

        internal void Send(string message) {
            Write(message);
        }

        private void Write(string message) {
            try {
                var m = Encryption.EncryptStringToBytesAes(message, a.Key, a.IV, e);
                s.Write(m, 0, m.Length);
            } catch {
                Dispose();
                Thread.CurrentThread.Abort();
            }
        }

        private string Read() {
            try {
                string result = null;
                var r = new byte[4096];

                while (result == null) {
                    var br = s.Read(r, 0, 4096);
                    if (br <= 0) {
                        Dispose();
                        Thread.CurrentThread.Abort();
                        return null;
                    }
                    var t = Encryption.DecryptStringFromBytesAes(r, br, a.Key, a.IV, e);
                    if (string.IsNullOrWhiteSpace(t)) continue;
                    result = t;
                }

                return result;
            }
            catch {
                Dispose();
                Thread.CurrentThread.Abort();
                return null;
            }
        }

        public void Dispose() {
            UserManager.UnRegisterClient(this);
            c.Close();
        }
    }
}