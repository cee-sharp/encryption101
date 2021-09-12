using System.Collections.Generic;
using NUnit.Framework;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("AES")]
    public class AesTests
    {
        [Test]
        [TestCaseSource(nameof(AesEncryptTestCases))]
        public void AesEncrypt_WithValidData_ShouldReturnEncryptedString(string text, string password)
        {
            var result = AES101.EncryptString(text, password);
            Assert.IsNotNull(result);
        }

        [Test]
        [TestCaseSource(nameof(AesEncryptTestCases))]
        public void AesDecrypt_WithValidData_ShouldReturnDecryptedString(string text, string password)
        {
            var encryptString = AES101.EncryptString(text, password);
            Assert.IsNotNull(encryptString);
            var result = AES101.DecryptString(encryptString, password);
            Assert.IsNotNull(result);
            Assert.AreEqual(text, result);
        }

        private static IEnumerable<TestCaseData> AesEncryptTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData("Hello Word", "34 2r3zbhza2734ph23r7h"),
                    new TestCaseData("!/§tpwkme8rb3ö4b", "sdfjhslkdfjh234872634876324"),
                    new TestCaseData("XXXYYYZZZ23651234623412341237548725612512751254172547543716253478156324", "2348626sahgjhsagfd"),
                    new TestCaseData(" ", "sdtua4jtam8jHGFJHVzpn34jäeöwg3rnujcnbefjh"),
                    new TestCaseData("µµµµßßööääÜÜ", "(O/T24hjncös97e5vrl3b&Rv2 f")
                };
                return testCaseData;
            }
        }
    }
}

