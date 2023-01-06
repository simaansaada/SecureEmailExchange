

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
/**************************************************
*						  *
*	Camellia Block Encryption Algorithm	  *
*	  in ANSI-C Language : Camellia.c	  *
*						  *
*	  Version M1.02 September 24 2001	  *
*  Copyright Mitsubishi Electric Corp 2000-2001  *
*						  *
**************************************************/

namespace Cryptography
{

    public class Camelia128CFB : Cipher
    {

        #region vars
        byte[] SIGMA = new byte[48] {
0xa0,0x9e,0x66,0x7f,0x3b,0xcc,0x90,0x8b,
0xb6,0x7a,0xe8,0x58,0x4c,0xaa,0x73,0xb2,
0xc6,0xef,0x37,0x2f,0xe9,0x4f,0x82,0xbe,
0x54,0xff,0x53,0xa5,0xf1,0xd3,0x6f,0x1c,
0x10,0xe5,0x27,0xfa,0xde,0x68,0x2d,0x1d,
0xb0,0x56,0x88,0xc2,0xb3,0xe6,0xc1,0xfd };

		int[] KSFT1 = new int[26] {
0,64,0,64,15,79,15,79,30,94,45,109,45,124,60,124,77,13,
94,30,94,30,111,47,111,47 };
		int[] KIDX1= new int[26]{
0,0,4,4,0,0,4,4,4,4,0,0,4,0,4,4,0,0,0,0,4,4,0,0,4,4 };
		int[] KSFT2= new int[34]{
0,64,0,64,15,79,15,79,30,94,30,94,45,109,45,109,60,124,
60,124,60,124,77,13,77,13,94,30,94,30,111,47,111,47 };
		int[] KIDX2= new int[34]{
0,0,12,12,8,8,4,4,8,8,12,12,0,0,4,4,0,0,8,8,12,12,
0,0,4,4,8,8,4,4,0,0,12,12 };

		byte[] SBOX = new byte[256]{
112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
 35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
 20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
 16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
 82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
 64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158 };

        #endregion
        #region sboxes
        byte SBOX1(int n) { return SBOX[(n)]; }
        byte SBOX2(int n) { return (byte)((SBOX[(n)] >> 7 ^ SBOX[(n)] << 1) & 0xff); }
        byte SBOX3(int n) { return (byte)((SBOX[(n)] >> 1 ^ SBOX[(n)] << 7) & 0xff); }
        byte SBOX4(int n) { return SBOX[((n) << 1 ^ (n) >> 7) & 0xff]; }
        #endregion

        void Camellia_Encrypt(int n, byte[] plaintext, byte[] key, byte[] c)
        {
            int i;

            XorBlock(plaintext, key, c);

            for (i = 0; i < 3; i++)
            {
                Camellia_Feistel(c.Skip(0).ToArray(), key.Skip(16 + (i << 4)).ToArray(), c.Skip(8).ToArray());
                Camellia_Feistel(c.Skip(8).ToArray(), key.Skip(24 + (i << 4)).ToArray(), c.Skip(0).ToArray());
            }

            Camellia_FLlayer(c, key.Skip(64).ToArray(), key.Skip(72).ToArray());

            for (i = 0; i < 3; i++)
            {
                Camellia_Feistel(c.Skip(0).ToArray(), key.Skip(80 + (i << 4)).ToArray(), c.Skip(8).ToArray());
                Camellia_Feistel(c.Skip(8).ToArray(), key.Skip(88 + (i << 4)).ToArray(), c.Skip(0).ToArray());
            }

            Camellia_FLlayer(c, key.Skip(128).ToArray(), key.Skip(136).ToArray());

            for (i = 0; i < 3; i++)
            {
                Camellia_Feistel(c.Skip(0).ToArray(), key.Skip(144 + (i << 4)).ToArray(), c.Skip(8).ToArray());
                Camellia_Feistel(c.Skip(8).ToArray(), key.Skip(152 + (i << 4)).ToArray(), c.Skip(0).ToArray());
            }

            if (n == 128)
            {
                SwapHalf(c);
                XorBlock(c, key.Skip(192).ToArray(), c);
            }
            else
            {
                Camellia_FLlayer(c, key.Skip(192).ToArray(), key.Skip(200).ToArray());

                for (i = 0; i < 3; i++)
                {
                    Camellia_Feistel(c.Skip(0).ToArray(), key.Skip(208 + (i << 4)).ToArray(), c.Skip(8).ToArray());
                    Camellia_Feistel(c.Skip(8).ToArray(), key.Skip(216 + (i << 4)).ToArray(), c.Skip(0).ToArray());
                }

                SwapHalf(c);
                XorBlock(c, key.Skip(256).ToArray(), c);
            }
        }
        void Camellia_Decrypt(int n, byte[] c, byte[] e, byte[] p)
        {
            int i;

            if (n == 128)
            {
                XorBlock(c, e.Skip(192).ToArray(), p);
            }
            else
            {
                XorBlock(c, e.Skip(256).ToArray(), p);

                for (i = 2; i >= 0; i--)
                {
                    Camellia_Feistel(p.Skip(0).ToArray(), e.Skip(216 + (i << 4)).ToArray(), p.Skip(8).ToArray());
                    Camellia_Feistel(p.Skip(8).ToArray(), e.Skip(208 + (i << 4)).ToArray(), p);
                }

                Camellia_FLlayer(p, e.Skip(200).ToArray(), e.Skip(192).ToArray());
            }

            for (i = 2; i >= 0; i--)
            {
                Camellia_Feistel(p, e.Skip(152 + (i << 4)).ToArray(), p.Skip(8).ToArray());
                Camellia_Feistel(p.Skip(8).ToArray(), e.Skip(144 + (i << 4)).ToArray(), p);
            }

            Camellia_FLlayer(p, e.Skip(136).ToArray(), e.Skip(128).ToArray());

            for (i = 2; i >= 0; i--)
            {
                Camellia_Feistel(p, e.Skip(88 + (i << 4)).ToArray(), p.Skip(8).ToArray());
                Camellia_Feistel(p.Skip(8).ToArray(), e.Skip(80 + (i << 4)).ToArray(), p);
            }

            Camellia_FLlayer(p, e.Skip(72).ToArray(), e.Skip(64).ToArray());

            for (i = 2; i >= 0; i--)
            {
                Camellia_Feistel(p, e.Skip(24 + (i << 4)).ToArray(), p.Skip(8).ToArray());
                Camellia_Feistel(p.Skip(8).ToArray(), e.Skip(16 + (i << 4)).ToArray(), p);
            }

            SwapHalf(p);
            XorBlock(p, e.Skip(0).ToArray(), p);
        }
        void Camellia_Feistel(byte[] x, byte[] k, byte[] y)
        {
            byte[] t = new byte[8];

            t[0] = SBOX1(x[0] ^ k[0]);
            t[1] = SBOX2(x[1] ^ k[1]);
            t[2] = SBOX3(x[2] ^ k[2]);
            t[3] = SBOX4(x[3] ^ k[3]);
            t[4] = SBOX2(x[4] ^ k[4]);
            t[5] = SBOX3(x[5] ^ k[5]);
            t[6] = SBOX4(x[6] ^ k[6]);
            t[7] = SBOX1(x[7] ^ k[7]);

            y[0] ^= (byte)(t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]);
            y[1] ^= (byte)(t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7]);
            y[2] ^= (byte)(t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7]);
            y[3] ^= (byte)(t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6]);
            y[4] ^= (byte)(t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7]);
            y[5] ^= (byte)(t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7]);
            y[6] ^= (byte)(t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7]);
            y[7] ^= (byte)(t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6]);
        }

        void Camellia_FLlayer(byte[] x, byte[] kl, byte[] kr)
        {
            long[] t = new long[4], u = new long[4], v = new long[4];

            ByteWord(x, t);
            ByteWord(kl, u);
            ByteWord(kr, v);

            t[1] ^= (t[0] & u[0]) << 1 ^ (t[0] & u[0]) >> 31;
            t[0] ^= t[1] | u[1];
            t[2] ^= t[3] | v[1];
            t[3] ^= (t[2] & v[0]) << 1 ^ (t[2] & v[0]) >> 31;

            WordByte(t, x);
        }

        void ByteWord(byte[] x, long[] y)
        {
            int i;
            for (i = 0; i < 4; i++)
            {
                y[i] = ((long)x[(i << 2) + 0] << 24) + ((long)x[(i << 2) + 1] << 16)
                    + ((long)x[(i << 2) + 2] << 8) + ((long)x[(i << 2) + 3] << 0);
            }
        }

        void WordByte(long[] x, byte[] y)
        {
            int i;
            for (i = 0; i < 4; i++)
            {
                y[(i << 2) + 0] = (byte)(x[i] >> 24 & 0xff);
                y[(i << 2) + 1] = (byte)(x[i] >> 16 & 0xff);
                y[(i << 2) + 2] = (byte)(x[i] >> 8 & 0xff);
                y[(i << 2) + 3] = (byte)(x[i] >> 0 & 0xff);
            }
        }

        void RotBlock(long[] x, int n, long[] y)
        {
            int r;
            r = (n & 31);
            if (r == 1)
            {
                y[0] = x[((n >> 5) + 0) & 3] << r ^ x[((n >> 5) + 1) & 3] >> (32 - r);
                y[1] = x[((n >> 5) + 1) & 3] << r ^ x[((n >> 5) + 2) & 3] >> (32 - r);
            }
            else
            {
                y[0] = x[((n >> 5) + 0) & 3];
                y[1] = x[((n >> 5) + 1) & 3];
            }
        }

        void SwapHalf(byte[] x)
        {
            byte t;
            int i;
            for (i = 0; i < 8; i++)
            {
                t = x[i];
                x[i] = x[8 + i];
                x[8 + i] = t;
            }
        }

        void XorBlock(byte[] x, byte[] y, byte[] z)
        {
            int i;
            for (i = 0; i < 16; i++) z[i] = (byte)(x[i] ^ y[i]);
        }


        private byte[] cipherkey { get; set; }


        public Camelia128CFB(string cipherkeys)
        {
            this.cipherkey = new byte[128];
            byte[] gotcipher=Encoding.UTF8.GetBytes(cipherkeys);
            for(int i=0;i< gotcipher.Length; i++)
            {
                cipherkey[i] = gotcipher[i];
            }
            for(int i= gotcipher.Length; i < 128; i++)
            {
                cipherkey[i] = 0;
            }
        }
        public byte[] Decrypt(byte[] ciphertext)
        {
            return Convert.FromBase64String(Encoding.UTF8.GetString(ciphertext));
        }
        public string Encrypt(string plaintext)
        {
            byte[] preproccessedplaintext = new byte[128];
            byte[] gottenplaintext = Encoding.UTF8.GetBytes(plaintext);
            for (int i = 0; i < gottenplaintext.Length; i++)
            {
                preproccessedplaintext[i] = gottenplaintext[i];
            }
            for (int i = gottenplaintext.Length; i < 128; i++)
            {
                preproccessedplaintext[i] = 0;
            }
            return Encoding.UTF8.GetString(Encrypt(preproccessedplaintext));
        }
        public byte[] Encrypt(byte[] plaintext)
        {
            //return Encoding.UTF8.GetBytes(Convert.ToBase64String(plaintext));
            byte[] plain  =new byte[16] { 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] key  =new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] result  =new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            Camellia_Es
            Camellia_Encrypt(128, plaintext, result, cipherkey);
            return result;
        }
    }
}
