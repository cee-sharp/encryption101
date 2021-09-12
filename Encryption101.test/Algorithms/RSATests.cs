using System.Text;
using NUnit.Framework;
using Encryption101;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("RSA")]
    public class RSATests
    {
        [Test]
        public void GenerateRSAKeys()
        {
            var keys = RSA101.GenerateKeys(2048);
            Assert.IsNotNull(keys);
            Assert.IsNotNull(keys.PublicKey);
            Assert.IsNotNull(keys.PrivateKey);
        }
        [Test]
        public void Encrypt_WithValidData_ShouldReturnEncryptedBytes()
        {
            var keys = RSA101.GenerateKeys(2048);
            var encryptedData = RSA101.Encrypt(Encoding.UTF8.GetBytes("test"), keys.PrivateKey);
            Assert.IsNotNull(encryptedData);
        }
        [Test]
        public void Decrypt_WithValidData_ShouldReturnDecryptedBytes()
        {
            var keys = RSA101.GenerateKeys(2048);
            var data = Encoding.UTF8.GetBytes("test");
            var encryptedData = RSA101.Encrypt(data, keys.PublicKey);
            Assert.IsNotNull(encryptedData);
            var decryptedData = RSA101.Decrypt(encryptedData, keys.PrivateKey);
            Assert.AreEqual(data, decryptedData);
        }
        [Test]
        public void Encrypt_WithValidData_ShouldReturnEncryptedString()
        {
            var keys = RSA101.GenerateKeys(2048);
            var encryptedData = RSA101.Encrypt("test", keys.PrivateKey);
            Assert.IsNotNull(encryptedData);
        }
        [Test]
        public void Decrypt_WithValidData_ShouldReturnDecryptedString()
        {
            var keys = RSA101.GenerateKeys(2048);
            var data = "test";
            var encryptedData = RSA101.Encrypt(data, keys.PublicKey);
            Assert.IsNotNull(encryptedData);
            var decryptedData = RSA101.Decrypt(encryptedData, keys.PrivateKey);
            Assert.AreEqual(data, decryptedData);
        }
        [Test]
        public void SignData_WithValidData_ShouldReturnSignString()
        {
            var keys = RSA101.GenerateKeys(2048);
            var encryptedData = RSA101.Encrypt("test", keys.PrivateKey);
            Assert.IsNotNull(encryptedData);
        }
        [Test]
        public void VerifyData_WithValidData_ShouldReturnTrue()
        {
            var keys = RSA101.GenerateKeys(2048);
            var data = "test";
            var signData = RSA101.SignData(data, keys.PrivateKey);
            Assert.IsNotNull(signData);
            var isCorrect = RSA101.VerifyData(data, signData, keys.PublicKey);
            Assert.IsTrue(isCorrect);
        }
    }
}
