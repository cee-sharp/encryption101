using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("AESThenHmac")]
    public class AesThenHmacTests
    {
        #region SimpleEncryptWithPassword
        [Test]
        [TestCaseSource(nameof(SimpleEncryptWithPasswordTestCases))]
        public void SimpleEncryptWithPassword_WithValidData_ShouldReturnEncryptedString(string message, string password)
        {
            var result = HMAC101.SimpleEncryptWithPassword(message, password);
            Assert.IsNotNull(result);
        }
        [Test]
        [TestCaseSource(nameof(SimpleEncryptWithPasswordTestCases))]
        public void SimpleEncryptWithPassword_WithValidData_ShouldReturnEncryptedBytes(string message, string password)
        {
            var bytesMessage = Encoding.Default.GetBytes(message);
            var result = HMAC101.SimpleEncryptWithPassword(bytesMessage, password);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > 0);
        }

        [Test]
        [TestCase("Artem", "")]
        [TestCase("Polischuk", null)]
        public void SimpleEncryptWithPassword_WithInvalidPassword_ShouldReturnArgumentException(string message, string password)
        {
            try
            {
                HMAC101.SimpleEncryptWithPassword(message, password);
                Assert.Fail("Password not validated");
            }
            catch (ArgumentException ex)
            {
                Assert.IsNotNull(ex);
            }
        }
        #endregion

        #region SimpleDecryptWithPassword
        [Test]
        [TestCaseSource(nameof(SimpleEncryptWithPasswordTestCases))]
        public void SimpleDecryptWithPassword_WithValidData_ShouldReturnEncryptedString(string message, string password)
        {
            var encryptString = HMAC101.SimpleEncryptWithPassword(message, password);
            var result = HMAC101.SimpleDecryptWithPassword(encryptString, password);
            Assert.IsNotNull(result);
            Assert.AreEqual(message, result);
        }
        [Test]
        [TestCaseSource(nameof(SimpleEncryptWithPasswordTestCases))]
        public void SimpleDecryptWithPassword_WithValidData_ShouldReturnEncryptedBytes(string message, string password)
        {
            var bytesMessage = Encoding.Default.GetBytes(message);
            var encryptByte = HMAC101.SimpleEncryptWithPassword(bytesMessage, password);
            var result = HMAC101.SimpleDecryptWithPassword(encryptByte, password);
            Assert.IsNotNull(result);
            var stringResult = Encoding.Default.GetString(result);
            Assert.AreEqual(message, stringResult);
        }

        [Test]
        [TestCase("Artem", "")]
        [TestCase("Polischuk", null)]
        public void SimpleDecryptWithPassword_WithInvalidPassword_ShouldReturnArgumentException(string message, string password)
        {
            try
            {
                HMAC101.SimpleDecryptWithPassword(message, password);
                Assert.Fail("Password not validated");
            }
            catch (ArgumentException ex)
            {
                Assert.IsNotNull(ex);
            }
        }
        #endregion

        #region SimpleEncrypt
        [Test]
        [TestCaseSource(nameof(SimpleEncryptTestCases))]
        public void SimpleEncrypt_WithValidData_ShouldReturnEncryptedString(byte[] message, byte[] password, byte[] authKey)
        {
            var result = HMAC101.SimpleEncrypt(message, password, authKey);
            Assert.IsNotNull(result);
        }

        public void SimpleEncrypt_WithInvalidCryptKeyLength_ShouldReturnArgumentException()
        {
            try
            {
                HMAC101.SimpleEncrypt(new byte[15], new byte[4], new byte[32]);
                Assert.Fail();
            }
            catch (ArgumentException ex)
            {
                Assert.IsNotNull(ex);
                Assert.AreEqual(ex.Message, "Key needs to be 256 bit!\r\nParameter name: cryptKey");
            }
        }
        [Test]
        public void SimpleEncrypt_WithInvalidAuthKeyLength_ShouldReturnArgumentException()
        {
            try
            {
                HMAC101.SimpleEncrypt(new byte[15], new byte[32], new byte[45]);
                Assert.Fail();
            }
            catch (Exception ex)
            {
                Assert.IsNotNull(ex);
            }
        }
        #endregion

        #region SimpleDecrypt
        [Test]
        [TestCaseSource(nameof(SimpleEncryptTestCases))]
        public void SimpleDecrypt_WithValidData_ShouldReturnEncryptedBytes(byte[] message, byte[] password, byte[] authKey)
        {
            var encryptByte = HMAC101.SimpleEncrypt(message, password, authKey);
            var result = HMAC101.SimpleDecrypt(encryptByte, password, authKey);
            Assert.IsNotNull(result);
            Assert.AreEqual(message, result);
        }

        [Test]
        public void SimpleDecrypt_WithInvalidCryptKeyLength_ShouldReturnArgumentException()
        {
            try
            {
                var encryptByte = HMAC101.SimpleEncrypt(new byte[15], new byte[32], new byte[32]);
                HMAC101.SimpleDecrypt(encryptByte, new byte[15], new byte[15]);
                Assert.Fail();
            }
            catch (Exception ex)
            {
                Assert.IsNotNull(ex);
            }
        }

        [Test]
        public void SimpleDecrypt_WithInvalidAuthKeyLength_ShouldReturnArgumentException()
        {
            try
            {
                var key = new byte[32] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                            21,22,23,24,25,26,2,28,29,30,31,32 };
                var auth = new byte[32] {201,202,203,204,205,206,207,208,209,210,211,212,213,
                                         214,215,216,217,218,219,220,221,222,223,224,225,226,
                                         22,228,229,230,231,232 };

                var data = new byte[16] { 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116 };

                var wrongKey = new byte[32] {31,32,33,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                            21,22,23,24,25,26,2,28,29,30,31,32 };


                var encryptByte = HMAC101.SimpleEncrypt(data, key, auth);
                HMAC101.SimpleDecrypt(encryptByte, wrongKey, auth);
                Assert.Fail("This line should not be reached during execution!");
            }
            catch (Exception ex)
            {
                Assert.IsNotNull(ex);
            }
        }
        #endregion

        #region TestCases
        private static IEnumerable<TestCaseData> SimpleEncryptTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData(Encoding.UTF8.GetBytes("Test"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv")),
                    new TestCaseData(Encoding.UTF8.GetBytes("Polischuk"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv")),
                    new TestCaseData(Encoding.UTF8.GetBytes("Artem"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv")),
                    new TestCaseData(Encoding.UTF8.GetBytes("Тестируем разную КІРїЛЁЦґ"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"),
                        Encoding.UTF8.GetBytes("IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"))
                };
                return testCaseData;
            }
        }
        private static IEnumerable<TestCaseData> SimpleEncryptWithPasswordTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData("Hello World", "HNtgQw0wAbZrURKx"),
                    new TestCaseData("aaabbAABBxxx12938", "iUaHmasVRY6xDIsZ"),
                    new TestCaseData(" ", "ghrw8z1mA6kOMQrFnwxq4321"),
                    new TestCaseData("äöÜÖäöÄÖßµµ", "IGwRDzLAr0BCQ6jvIGwRDzLAr0BCQ6jv"),
                    new TestCaseData("AAAA", "1234"),
                    new TestCaseData("AAAA", "333"),
                    new TestCaseData("AAAA", "55555"),
                };
                return testCaseData;
            }
        }
        #endregion
    }
}
