using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
{
  public static class KeyDerivation
  {
    public static byte[] DeriveFromKey(byte[] masterKey, int subKeyLength, ulong subKeyId, byte[] context)
    {
      var key = new byte[32];
      key.Initialize();
      Array.Copy(masterKey, 0, key, 0, masterKey.Length > 32 ? 32 : masterKey.Length);
      var ctx = new byte[8];
      ctx.Initialize();
      Array.Copy(context, 0, ctx, 0, context.Length > 8 ? 8 : context.Length);
      var subkey = new byte[subKeyLength];
      var bin = Marshal.AllocHGlobal(subkey.Length);
      var ret = SodiumLibrary.crypto_kdf_derive_from_key(bin, new UIntPtr((uint) subKeyLength), subKeyId, ctx, key);
      if (ret != 0)
        throw new InvalidOperationException($"Error derive sub key from master key. ({ret})");
      Marshal.Copy(bin, subkey, 0, subKeyLength);
      Marshal.FreeHGlobal(bin);
      return subkey;
    }
  }
}