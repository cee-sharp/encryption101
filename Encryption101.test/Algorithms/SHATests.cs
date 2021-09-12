using System;
using System.Collections.Generic;
using NUnit.Framework;
using Encryption101;

namespace Encryption101.test.Algorithms
{
    [TestFixture]
    [Category("SHA")]
    public class SHATests
    {

        [Test]
        [TestCaseSource(nameof(ComputeHashTestCases))]
        public void ComputeSHA1Hash_WithValidData_ShouldReturnSHAString(string text)
        {
            var result = SHA101.ComputeSHA1Hash(text);
            Assert.IsNotNull(result);
            Console.WriteLine(result);
        }

        [Test]
        [TestCaseSource(nameof(ComputeHashTestCases))]
        public void ComputeSHA256Hash_WithValidData_ShouldReturnSHAString(string text)
        {
            var result = SHA101.ComputeSHA256Hash(text);
            Assert.IsNotNull(result);
            Console.WriteLine(result);
        }
        private static IEnumerable<TestCaseData> ComputeHashTestCases
        {
            get
            {
                var testCaseData = new List<TestCaseData>
                {
                    new TestCaseData("Hello World"),
                    new TestCaseData("sfaosdjfh baksjdhf"),
                    new TestCaseData(" "),
                    new TestCaseData("2349812038876123096"),
                    new TestCaseData("ÄÖÜäöüöµµßß")
                };
                return testCaseData;
            }
        }

    }
}
