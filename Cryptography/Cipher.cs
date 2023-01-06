using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography
{
    /// <summary>
    /// a cipher factory interface to represent a base for Cipher.
    /// </summary>
    public interface Cipher
    {
        public byte[] Encrypt(byte[] plaintext);
        public byte[] Decrypt(byte[] ciphertext);
    }
}
