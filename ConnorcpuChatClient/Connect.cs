using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Windows;
using ConnorcpuChatCommon;

namespace ConnorcpuChatClient {
    internal class Connection {
        private static TcpClient client;
        private static AesCryptoServiceProvider Aes;
        private static readonly Encoding e = Encoding.UTF8;

        internal static bool Connected { get; private set; }

        /// <summary>
        /// Begins the connection to the chat server
        /// </summary>
        /// <param name="hostname">Hostname to connect to</param>
        /// <param name="port">Destination port</param>
        /// <param name="user">The username</param>
        /// <param name="pass">The password</param>
        internal static void Connect(string hostname, int port, string user, string pass) {
            try
            {
                // Initializes a new RSA cryptography class to allow the server to securely send you the symetrical encryption key
                var rsa = new RSACryptoServiceProvider(1024);
                // Gets the Csp blob from the rsa without a private key for transportation to the server
                var publickey = rsa.ExportCspBlob(false);

                // Connects the client to the server
                client = new TcpClient(hostname, port);
                // Gets the stream for use with server communication
                var s = client.GetStream();

                // Sends the csp to the server
                s.Write(new[] { (byte)publickey.Length }, 0, 1);
                s.Write(publickey, 0, publickey.Length);

                // Gets the AES key back from the server
                var aes = GetConnectionKey(s, rsa.ExportParameters(false));
                if (aes == null)
                {
                    return;
                }

                var euser = Encryption.EncryptStringToBytesAes(user + ":" + pass, aes.Key, aes.IV, e);
                s.Write(euser, 0, euser.Length);

                var r = new byte[4096];
                var br = s.Read(r, 0, 4096);
                if (br == 0) {
                    MessageBox.Show("The server unexpectedly closed the connection during login.");
                    return;
                }
                var uar = Encryption.DecryptStringFromBytesAes(r, br, aes.Key, aes.IV, e);

                if (uar.ToLower() != "IM_OLD_GREGG__PLEASED_TO_MEET_YA".ToLower())
                {
                    MessageBox.Show(uar.ToLower() == "USER_BANNED".ToLower()
                                        ? "Unfortunately, your username is banned from the server"
                                        : "Your username or password was incorrect");
                    return;
                }

                Aes = aes;
                Connected = true;

            }
            catch (Exception exception) {
                MessageBox.Show("There was an error connecting to the server.\n" + exception.Message);
            }
        }

        private static AesCryptoServiceProvider GetConnectionKey(NetworkStream s, RSAParameters decryption) {
            var csp = new AesCryptoServiceProvider();

            var dl = s.ReadByte();

            var d = new byte[dl];
            for (var i = 0; i < dl; ++i) {
                var c = s.ReadByte();
                if (c == -1) return null;
                d[i] = (byte) c;
            }
            csp.Key = Encryption.RSADecrypt(d, decryption, false);


            dl = s.ReadByte();
            d = new byte[dl];
            for (var i = 0; i < dl; ++i) {
                var c = s.ReadByte();
                if (c == -1) return null;
                d[i] = (byte) c;
            }
            csp.IV = Encryption.RSADecrypt(d, decryption, false);

            return csp;
        }
    }
}