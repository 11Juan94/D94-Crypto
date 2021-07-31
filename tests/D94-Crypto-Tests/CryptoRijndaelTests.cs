using System;
using Xunit;
using D94_Crypto;

namespace D94_Crypto_Tests
{
    public class CryptoRijndaelTests
    {
        private static string passPhrase = "UltraPrivateString";

        [Fact]
        public void TestEncrypt()
        {
            var b64EncriptedData = CryptoRijndael.Encrypt("Encrypt this data", passPhrase);
            Assert.NotNull(b64EncriptedData);
        }

        [Fact]
        public void TestEncryptDifferentValues()
        {
            var b64EncriptedData = CryptoRijndael.Encrypt("Encrypt this data", passPhrase);
            var b64EncriptedData2 = CryptoRijndael.Encrypt("Encrypt this data", passPhrase);
            Assert.NotEqual(b64EncriptedData, b64EncriptedData2);
        }
        [Fact]
        public void TestDecrypt()
        {
            var decrypted = CryptoRijndael.Decrypt("KuJFM+e3JWxb70jsfwFEa9tlNI+4rma/I3DEzWLn9WY=", passPhrase);
            Assert.Equal("Encrypt this data", decrypted);
        }
        [Fact]
        public void TestEncryptWithoutSalt()
        {
            var b64EncriptedData = CryptoRijndael.Encrypt("Encrypt this data", passPhrase, 0);
            Assert.NotNull(b64EncriptedData);
            var b64EncriptedData2 = CryptoRijndael.Encrypt("Encrypt this data", passPhrase, 0);
            Assert.Equal(b64EncriptedData, b64EncriptedData2);
        }
        [Fact]
        public void TestDecryptWithoutSalt()
        {
            var decrypted = CryptoRijndael.Decrypt("aPkQTTCVDlJKKtnq+r+4ovk6L3bPPumZ0W4VmBvq9ec=", passPhrase, 0);
            Assert.Equal("Encrypt this data", decrypted);
        }
    }
}
