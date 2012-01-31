using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ConnorcpuChatCommon;

namespace ConnorcpuChatServer {
    internal class ClientHandler {

        private static readonly Encoding e = Encoding.UTF8;

        /// <summary>
        /// Handles a newly accepted TCP client from the listener
        /// </summary>
        /// <param name="c">The client to handle</param>
        internal static void HandleClient(TcpClient c) {
            var rep = c.Client.RemoteEndPoint;
            try {
                // Get a networkstream to work with
                var s = c.GetStream();
                // Initialize a new RSA class to exchange the symetrical keys
                var rsa = new RSACryptoServiceProvider();
                // Get the RSA public key from the client
                var pk = GetPublicKey(s);
                // If the public key was null (e.g. the stream closed), toss out this client
                if (pk == null) {
                    return;
                }
                // If the key wasn't null, import it as the new key for the RSA class
                rsa.ImportCspBlob(pk);
                // Generate a new AES provider with a 256-bit key
                var aes = new AesCryptoServiceProvider {KeySize = 256};
                // Generate the Key and Initialization vector
                aes.GenerateKey();
                aes.GenerateIV();

                // Encrypt the AES Key and IV for transportation to the client
                var aeskey = Encryption.RSAEncrypt(aes.Key, rsa.ExportParameters(false), false);
                var aesiv = Encryption.RSAEncrypt(aes.IV, rsa.ExportParameters(false), false);

                // Write the key and iv to the stream
                s.Write(new[] {(byte) aeskey.Length}, 0, 1);
                s.Write(aeskey, 0, aeskey.Length);
                s.Write(new[] {(byte) aesiv.Length}, 0, 1);
                s.Write(aesiv, 0, aesiv.Length);

                // Read the username and password from the client
                var r = new byte[4096];
                var br = s.Read(r, 0, 4096);
                if (br == 0) return;
                var userpass = Encryption.DecryptStringFromBytesAes(r, br, aes.Key, aes.IV, e);

                // Split the data in two at the first colon to seperate username from password
                var userpass_ = userpass.Split(new[]{':'}, 2);

                // Turn the username and password into their own variables
                var user = userpass_[0];
                var pass = userpass_[1];

                // Attempt to authenticate the user
                var uar = Authentication.Authenticate(user, pass);

                // If the authentication wasn't successful...
                if (uar != UserAuthResult.Success) {
                    if (uar == UserAuthResult.Banned) {
                        // If the user was banned, tell them they are banned
                        var banm = Encryption.EncryptStringToBytesAes("USER_BANNED", aes.Key, aes.IV, e);
                        s.Write(banm, 0, banm.Length);
                    } else {
                        // If the user does not exist or the password was wrong, tell them they had bad credentials
                        var buop = Encryption.EncryptStringToBytesAes("BAD_CRED", aes.Key, aes.IV, e);
                        s.Write(buop, 0, buop.Length);
                    }

                    // Finally, send the client packing
                    c.Close();
                    return;
                }

                var smes = Encryption.EncryptStringToBytesAes("IM_OLD_GREGG__PLEASED_TO_MEET_YA", aes.Key, aes.IV, e);
                s.Write(smes, 0, smes.Length);

                Console.WriteLine("{0} authenticated successfully as {1}", rep, user);

                // Pass the client on to the sustainable client class
                var h = new Client(c, user, aes);
                h.Start();
            }
            catch (Exception exception) {
                // If there was an IO exception, write it to the console
                Console.WriteLine("Exception occured in client handler.\nClient: {1}\nDetails: {0}\n{2}",
                                  exception.GetType(), rep, exception.Message);
                if (c.Connected) c.Close();
            }
        }

        // Gets the public key for the RSA class from the stream
        private static byte[] GetPublicKey(Stream s) {
            // Get the ammount of bytes that need to be read
            var dl = s.ReadByte();
            if (dl == -1) return null;

            // Read the bytes
            var d = new byte[dl];
            for (var i = 0; i < dl; ++i) {
                var c = s.ReadByte();
                if (c == -1) return null;
                d[i] = (byte) c;
            }

            // Return the public key Csp blob
            return d;
        }
    }
}