using System.Text;
using NUnit.Framework;
using Sodium;

namespace Tests
{
  [TestFixture]
  public class KeyDerivationTest
  {
    [Test]
    public void KeyLengthTest()
    {
      var key = new byte[] { 0x1, 0x2, 0x5, 0x6 };

      for (int i = 16; i <= 64; ++i)
      for (ulong j = 0; j < 8888; ++j)
      {
        Assert.AreEqual(i, KeyDerivation.DeriveFromKey(key, i, j, Encoding.ASCII.GetBytes("abcd")).Length);
      }
    }
  }
}