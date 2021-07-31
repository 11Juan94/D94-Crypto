using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace D94_Crypto
{
   public static class CryptoRijndael
    {
        private static int PASSWORD_ITERATIONS = 2000;

        /// <summary>
        /// Merge two arrays of bytes and return the result of them.
        /// </summary>
        /// <param name="saltBytes">
        /// Byte array for salt (random bytes)
        /// </param>
        /// <param name="data">
        /// Byte array for data.
        /// </param>
        /// <returns>
        /// Byte array with the merge of inputs.
        /// </returns>
        private static byte[] MergeSaltAndData(byte[] saltBytes, byte[] data)
        {
            byte[] combined = new byte[saltBytes.Length + data.Length];
            Array.Copy(saltBytes, combined, saltBytes.Length);
            Array.Copy(data, 0, combined, saltBytes.Length, data.Length);
            return combined;
        }
        /// <summary>
        /// Encrypts specified plaintext using Rijndael symmetric key algorithm
        /// and returns a base64-encoded result.
        /// </summary>
        /// <param name="plainText">
        /// Plaintext value to be encrypted.
        /// </param>
        /// <param name="passPhrase">
        /// Passphrase from which a pseudo-random password will be derived. The
        /// derived password will be used to generate the encryption key.
        /// Passphrase can be any string. In this example we assume that this
        /// passphrase is an ASCII string.
        /// </param>
        /// <param name="saltLength">
        /// Number of bytes added in the input for randomize string encrypt.
        /// </param>
        /// <returns>
        /// Encrypted value formatted as a base64-encoded string.
        /// </returns>
        public static string Encrypt(string plainText, string passPhrase, int saltLength = 8)
        {
            byte[] passPhraseBytes = Encoding.UTF8.GetBytes(passPhrase);
            byte[] hashPhraseBytes = SHA256.Create().ComputeHash(passPhraseBytes);
            byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(plainText);
            if (saltLength > 0)
            {
                byte[] randomSaltBytes = new byte[saltLength];
                RandomNumberGenerator.Create().GetBytes(randomSaltBytes);
                bytesToBeEncrypted = MergeSaltAndData(randomSaltBytes, bytesToBeEncrypted);
            }
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhraseBytes, hashPhraseBytes, PASSWORD_ITERATIONS);
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.Mode = CipherMode.CBC;
                AES.BlockSize = 128;
                AES.KeySize = 256;
                AES.Key = password.GetBytes(AES.KeySize / 8);
                AES.IV = password.GetBytes(AES.BlockSize / 8);
                AES.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    cs.FlushFinalBlock();
                    cs.Close();
                    byte[] cipherTextBytes = ms.ToArray();
                    string cipherText = Convert.ToBase64String(cipherTextBytes);
                    return cipherText;
                }
            }
        }

        /// <summary>
        /// Decrypts specified ciphertext using Rijndael symmetric key algorithm.
        /// </summary>
        /// <param name="cipherText">
        /// Base64-formatted ciphertext value.
        /// </param>
        /// <param name="passPhrase">
        /// Passphrase from which a pseudo-random password will be derived. The
        /// derived password will be used to generate the encryption key.
        /// Passphrase can be any string. In this example we assume that this
        /// passphrase is an ASCII string.
        /// </param>
        /// <param name="saltLength">
        /// Number of bytes removed in the output for randomize string.
        /// </param>
        /// <returns>
        /// Decrypted string value.
        /// </returns>
        /// <remarks>
        /// Most of the logic in this function is similar to the Encrypt
        /// logic. In order for decryption to work, all parameters of this function
        /// - except cipherText value - must match the corresponding parameters of
        /// the Encrypt function which was called to generate the
        /// ciphertext.
        /// </remarks>
        public static string Decrypt(string cipherText, string passPhrase, int saltLength = 8)
        {
            byte[] passPhraseBytes = Encoding.UTF8.GetBytes(passPhrase);
            byte[] hashPhraseBytes = SHA256.Create().ComputeHash(passPhraseBytes);
            byte[] bytesToBeDecrypted = Convert.FromBase64String(cipherText);
            Rfc2898DeriveBytes password = new Rfc2898DeriveBytes(passPhraseBytes, hashPhraseBytes, PASSWORD_ITERATIONS);
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.Mode = CipherMode.CBC;
                AES.BlockSize = 128;
                AES.KeySize = 256;
                AES.Key = password.GetBytes(AES.KeySize / 8);
                AES.IV = password.GetBytes(AES.BlockSize / 8);
                AES.Padding = PaddingMode.PKCS7;
                using (MemoryStream ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    cs.FlushFinalBlock();
                    cs.Close();
                    byte[] decryptedBytes = ms.ToArray();
                    string decodedString = Encoding.UTF8.GetString(decryptedBytes, saltLength, decryptedBytes.Length - saltLength);
                    return decodedString;
                }
            }
        }
    }
}
