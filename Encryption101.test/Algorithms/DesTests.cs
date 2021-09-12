using System.Collections.Generic;
using NUnit.Framework;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("DES")]
    public class DesTests
    {
        [Test]
        [TestCaseSource(nameof(DesEncryptTestCases))]
        public void DesEncrypt_WithValidData_ShouldReturnEncryptedString(string text, string password)
        {
            var result = DES101.Encrypt(text, password);
            Assert.IsNotNull(result);
        }

        [Test]
        [TestCaseSource(nameof(DesEncryptTestCases))]
        public void DesDecrypt_WithValidData_ShouldReturnDecryptedString(string text, string password)
        {
            var encryptString = DES101.Encrypt(text, password);
            Assert.IsNotNull(encryptString);
            var result = DES101.Decrypt(encryptString, password);
            Assert.IsNotNull(result);
            Assert.AreEqual(text, result);
        }

        private static IEnumerable<TestCaseData> DesEncryptTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData("Hello Word", "password"),
                    new TestCaseData(" ", "safe password"),
                    new TestCaseData("aaabbbAABBB123", "more safe password"),
                    new TestCaseData("23efhbw374p23", "safe as nighmare"),
                    new TestCaseData("µµµäöüÜÖß", "wow")
                };
                return testCaseData;
            }
        }
    }
}

