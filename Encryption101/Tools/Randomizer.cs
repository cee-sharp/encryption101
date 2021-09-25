using System;
using System.Text;

namespace Encryption101.Tools
{
    public class Randomizer
    {
        /// <summary>
        /// Generate random number with a given number of digits
        /// </summary>
        /// <param name="digits">Number of digits for the</param>
        /// <returns></returns>
        public static string GenerateNumber(int digits)
        {
            if (digits <= 0)
                throw new ArgumentOutOfRangeException("Number o digits must be > 0");

            var random = new Random((int)DateTime.Now.Ticks);
            var output = new StringBuilder();
            for (var i = 0; i < digits; i++)
            {
                output.Append(random.Next(0, 10));
            }
            return output.ToString();
        }
    }
}
