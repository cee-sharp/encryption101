using System;
using System.Collections.Generic;
using NUnit.Framework;
using Encryption101;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("MD5")]
    public class MD5Tests
    {

        #region CalculateMD5Hash
        [Test]
        [TestCaseSource(nameof(CalculateMD5HashTestCases))]
        public void CalculateMD5Hash_WithValidData_ShouldReturnMD5String(string text)
        {
            var result = MD5101.GetMd5Hash(text);
            Assert.IsNotNull(result);
            Console.WriteLine(result);
        }
        #endregion

        #region IsValidMD5
        [Test]
        [TestCaseSource(nameof(CalculateMD5HashTestCases))]
        public void IsValidMD5_WithInvalidMD5_ShouldReturnFalse(string text)
        {
            var md5Hash = "012345";
            var result = MD5101.IsValidMD5(md5Hash);
            Assert.False(result);
        }

        [Test]
        [TestCaseSource(nameof(CalculateMD5HashTestCases))]
        public void IsValidMD5_WithValidMD5_ShouldReturnTrue(string text)
        {
            var md5Hash = MD5101.GetMd5Hash(text);
            Assert.IsNotNull(md5Hash);
            var result = MD5101.IsValidMD5(md5Hash);
            Assert.True(result);
        }
        #endregion

        private static IEnumerable<TestCaseData> CalculateMD5HashTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData("a"),
                    new TestCaseData("sdfjsdfjh"),
                    new TestCaseData("xxxaa1231234"),
                    new TestCaseData("äÜÖßµdsfj"),
                    new TestCaseData("Hello World")
                };
                return testCaseData;
            }
        }
    }
}
