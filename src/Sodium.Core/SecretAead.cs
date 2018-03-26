using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Sodium.Exceptions;

namespace Sodium
{
  /// <summary>Authenticated Encryption with Additional Data.</summary>
  public class SecretAead
  {
    private readonly IBufferPool _bufferPool;
    private const int KEYBYTES = 32;
    private const int NPUBBYTES = 24;
    private const int ABYTES = 16;

    public SecretAead(IBufferPool bufferPool)
    {
      _bufferPool = bufferPool;
    }

    //TODO: we could implement a method which increments the nonce.

    /// <summary>Generates a random 8 byte nonce.</summary>
    /// <returns>Returns a byte array with 8 random bytes.</returns>
    public static byte[] GenerateNonce()
    {
      return SodiumCore.GetRandomBytes(NPUBBYTES);
    }

    /// <summary>
    /// Encrypts a message with an authentication tag and additional data.
    /// </summary>
    /// <param name="message">The message to be encrypted.</param>
    /// <param name="nonce">The 8 byte nonce.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
    /// <returns>The encrypted message with additional data.</returns>
    /// <remarks>The nonce should never ever be reused with the same key.</remarks>
    /// <remarks>The recommended way to generate it is to use GenerateNonce() for the first message, and increment it for each subsequent message using the same key.</remarks>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="AdditionalDataOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Encrypt(byte[] message, byte[] nonce, byte[] key, byte[] additionalData = null)
    {
      //additionalData can be null
      if (additionalData == null)
        additionalData = new byte[0x00];

      //validate the length of the key
      if (key == null || key.Length != KEYBYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEYBYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NPUBBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

//      //validate the length of the additionalData
//      if (additionalData.Length > ABYTES || additionalData.Length < 0)
//        throw new AdditionalDataOutOfRangeException(
//          string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

      var cipher = new byte[message.Length + ABYTES];
      var bin = Marshal.AllocHGlobal(cipher.Length);
      long cipherLength;

      var ret = SodiumLibrary.crypto_aead_xchacha20poly1305_ietf_encrypt(bin, out cipherLength, message, message.Length, additionalData, additionalData.Length, null,
        nonce, key);

      Marshal.Copy(bin, cipher, 0, (int) cipherLength);
      Marshal.FreeHGlobal(bin);

      if (ret != 0)
        throw new CryptographicException("Error encrypting message.");

      if (cipher.Length == cipherLength)
        return cipher;

      //remove the trailing nulls from the array
      var tmp = new byte[cipherLength];
      Array.Copy(cipher, 0, tmp, 0, (int)cipherLength);

      return tmp;
    }


    /// <summary>
    /// Encrypts a message with an authentication tag and additional data.
    /// </summary>
    /// <param name="message">The message to be encrypted.</param>
    /// <param name="nonce">The 8 byte nonce.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
    /// <returns>The encrypted message with additional data.</returns>
    /// <remarks>The nonce should never ever be reused with the same key.</remarks>
    /// <remarks>The recommended way to generate it is to use GenerateNonce() for the first message, and increment it for each subsequent message using the same key.</remarks>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="AdditionalDataOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public ArraySegment<byte> Encrypt(ArraySegment<byte> message, byte[] nonce, byte[] key, ArraySegment<byte> additionalData = default)
    {
      //additionalData can be null
      if (additionalData.Array == null)
        additionalData = new ArraySegment<byte>(Array.Empty<byte>());

      //validate the length of the key
      if (key == null || key.Length != KEYBYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEYBYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NPUBBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

      //      //validate the length of the additionalData
      //      if (additionalData.Length > ABYTES || additionalData.Length < 0)
      //        throw new AdditionalDataOutOfRangeException(
      //          string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

      long cipherLength;

      var hMsg = GCHandle.Alloc(message.Array, GCHandleType.Pinned);
      var hAData = GCHandle.Alloc(additionalData.Array, GCHandleType.Pinned);


      var msg = _bufferPool.Rent(message.Count + ABYTES);
      var hCipher = GCHandle.Alloc(msg, GCHandleType.Pinned);

      var ret = SodiumLibrary.crypto_aead_xchacha20poly1305_ietf_encrypt(hCipher.AddrOfPinnedObject(), out cipherLength,
        hMsg.AddrOfPinnedObject() + message.Offset, message.Count, hAData.AddrOfPinnedObject() + additionalData.Offset,
        additionalData.Count, null, nonce, key);

      hMsg.Free();
      hAData.Free();
      hCipher.Free();

      if (ret != 0)
        throw new CryptographicException("Error encrypting message.");

      return new ArraySegment<byte>(msg, 0, (int) cipherLength);
    }

    /// <summary>
    /// Decrypts a cipher with an authentication tag and additional data.
    /// </summary>
    /// <param name="cipher">The cipher to be decrypted.</param>
    /// <param name="nonce">The 8 byte nonce.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
    /// <returns>The decrypted cipher.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="AdditionalDataOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public static byte[] Decrypt(byte[] cipher, byte[] nonce, byte[] key, byte[] additionalData = null)
    {
      //additionalData can be null
      if (additionalData == null)
        additionalData = new byte[0x00];

      //validate the length of the key
      if (key == null || key.Length != KEYBYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEYBYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NPUBBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

//      //validate the length of the additionalData
//      if (additionalData.Length > ABYTES || additionalData.Length < 0)
//        throw new AdditionalDataOutOfRangeException(
//          string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

      var message = new byte[cipher.Length - ABYTES];
      var bin = Marshal.AllocHGlobal(message.Length);
      long messageLength;

      var ret = SodiumLibrary.crypto_aead_xchacha20poly1305_ietf_decrypt(bin, out messageLength, null, cipher, cipher.Length,
        additionalData, additionalData.Length, nonce, key);

      Marshal.Copy(bin, message, 0, (int)messageLength);
      Marshal.FreeHGlobal(bin);

      if (ret != 0)
        throw new CryptographicException("Error decrypting message.");

      if (message.Length == messageLength)
        return message;

      //remove the trailing nulls from the array
      var tmp = new byte[messageLength];
      Array.Copy(message, 0, tmp, 0, (int)messageLength);

      return tmp;
    }

    /// <summary>
    /// Decrypts a cipher with an authentication tag and additional data.
    /// </summary>
    /// <param name="cipher">The cipher to be decrypted.</param>
    /// <param name="nonce">The 8 byte nonce.</param>
    /// <param name="key">The 32 byte key.</param>
    /// <param name="additionalData">The additional data; may be null, otherwise between 0 and 16 bytes.</param>
    /// <returns>The decrypted cipher.</returns>
    /// <exception cref="KeyOutOfRangeException"></exception>
    /// <exception cref="NonceOutOfRangeException"></exception>
    /// <exception cref="AdditionalDataOutOfRangeException"></exception>
    /// <exception cref="CryptographicException"></exception>
    public ArraySegment<byte> Decrypt(ArraySegment<byte> cipher, byte[] nonce, byte[] key, ArraySegment<byte> additionalData)
    {
      //validate the length of the key
      if (key == null || key.Length != KEYBYTES)
        throw new KeyOutOfRangeException("key", (key == null) ? 0 : key.Length,
          string.Format("key must be {0} bytes in length.", KEYBYTES));

      //validate the length of the nonce
      if (nonce == null || nonce.Length != NPUBBYTES)
        throw new NonceOutOfRangeException("nonce", (nonce == null) ? 0 : nonce.Length,
          string.Format("nonce must be {0} bytes in length.", NPUBBYTES));

      //additionalData can be null
      GCHandle hAddData;
      IntPtr pAddData;
      int adataLength;
      if (additionalData.Array == null)
      {
        hAddData = GCHandle.Alloc(Array.Empty<byte>(), GCHandleType.Pinned);
        pAddData = hAddData.AddrOfPinnedObject();
        adataLength = 0;
      }
      else
      {
        hAddData = GCHandle.Alloc(additionalData.Array, GCHandleType.Pinned);
        pAddData = hAddData.AddrOfPinnedObject() + additionalData.Offset;
        adataLength = additionalData.Count;
      }



      //      //validate the length of the additionalData
      //      if (additionalData.Length > ABYTES || additionalData.Length < 0)
      //        throw new AdditionalDataOutOfRangeException(
      //          string.Format("additionalData must be between {0} and {1} bytes in length.", 0, ABYTES));

      var message = _bufferPool.Rent(cipher.Count - ABYTES);
      var hMsg = GCHandle.Alloc(message, GCHandleType.Pinned);
      var hCipher = GCHandle.Alloc(cipher.Array, GCHandleType.Pinned);

      var ret = SodiumLibrary.crypto_aead_xchacha20poly1305_ietf_decrypt(hMsg.AddrOfPinnedObject(),
        out long messageLength, null, hCipher.AddrOfPinnedObject() + cipher.Offset, cipher.Count,
        pAddData, adataLength, nonce, key);

      hMsg.Free();
      hAddData.Free();
      hCipher.Free();

      if (ret != 0)
        throw new CryptographicException("Error decrypting message.");

      return new ArraySegment<byte>(message, 0, (int) messageLength);
    }
  }
}
